//! Tuck ↔ Anaphase interaction bridge.
//!
//! # Design Principle
//!
//! **极致解耦**: Tuck does NOT depend on anaphase-helix directly. This module
//! defines Tuck-side types and traits for interacting with Anaphase's
//! orchestration layer. The actual transport (gRPC, HTTP, in-process) is
//! handled by an adapter layer in the deployment environment.
//!
//! **三层闸门对齐**: Anaphase's hitl.rs defines three gates:
//! 1. Tool audit (入库门) — Tentacle plugin registry
//! 2. HITL (执行闸) — human confirmation for high-risk actions
//! 3. Tuck (边缘物理闸) — hard real-time security decision
//!
//! This module implements gate #3 (Tuck) and provides integration points
//! for gate #2 (HITL escalation).
//!
//! **按需驱动**: Tuck only makes a decision when Anaphase explicitly requests
//! a security gate check. Pass decisions are not notified to Anaphase (it
//! just continues execution). Reject/HITL/HardOverride decisions block
//! execution and return a structured response.
//!
//! # Interaction Model
//!
//! ```text
//! Anaphase (orchestration)
//!   │
//!   │ 1. SecurityGateRequest { pfp, identity_label, action_type, context }
//!   ▼
//! Tuck (security gate)
//!   │
//!   │ 2. Hard real-time decide() (sub-μs, reads 4-byte PFP)
//!   │
//!   ├─ Pass → inject credential (if identity_label present) → return Pass
//!   ├─ Reject → return Reject { reason } (Anaphase blocks execution)
//!   ├─ NeedHumanConfirm → return HITLRequired (Anaphase escalates to HITL gate)
//!   └─ HardOverridePass → return HardOverride (emergency, audit logged)
//!   │
//!   │ 3. SecurityGateResponse { decision, credential_injected, audit_entry_id }
//!   ▼
//! Anaphase (continues or blocks based on decision)
//! ```

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Decision, OverrideFlag, PfpHeader, RiskLevel, SecurityPolicy};
use crate::audit::AuditLog;
use crate::credential::{CredentialError, CredentialStore, IdentityLabel};
use crate::injection::{InjectionTarget, OutboundRequest};
use crate::sap::{LruReplayCache, SignatureVerifier, SapHeader, SapDecision, decide_with_sap};

// ============================================================================
// Security Gate Request — Anaphase → Tuck
// ============================================================================

/// Security gate request from Anaphase to Tuck.
///
/// Anaphase sends this before executing any tool/action that goes through
/// the security gate. Tuck makes the hard real-time decision and optionally
/// injects credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGateRequest {
    /// Trace ID for end-to-end observability.
    pub trace_id: Uuid,
    /// Source identifier (e.g., "anaphase_orchestrator_01").
    pub source_id: String,
    /// 4-byte PFP header (physical fact: modality, risk level, stance, edge).
    pub pfp: [u8; 4],
    /// Optional SAP header (28 bytes, for replay protection + signature verification).
    pub sap: Option<[u8; 28]>,
    /// Optional identity label for credential injection.
    /// If present and decision is Pass, Tuck injects the credential.
    pub identity_label: Option<String>,
    /// Action type (cognitive/render/executive/sensor_feed).
    pub action_type: String,
    /// Human-readable action description (for audit logging).
    pub action_description: String,
    /// Optional injection target (where to inject the credential).
    /// If None, credential is returned in the response for Anaphase to inject.
    pub injection_target: Option<InjectionTargetConfig>,
}

/// Injection target configuration (simplified for wire format).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InjectionTargetConfig {
    /// HTTP header injection.
    HttpHeader { name: String },
    /// Bearer token in Authorization header.
    BearerToken,
    /// Query parameter injection.
    QueryParam { name: String },
    /// JSON body field injection.
    BodyField { path: String },
    /// Basic auth injection.
    BasicAuth { username: String },
}

impl From<&InjectionTargetConfig> for InjectionTarget {
    fn from(config: &InjectionTargetConfig) -> Self {
        match config {
            InjectionTargetConfig::HttpHeader { name } => InjectionTarget::header(name),
            InjectionTargetConfig::BearerToken => InjectionTarget::BearerToken,
            InjectionTargetConfig::QueryParam { name } => InjectionTarget::query_param(name),
            InjectionTargetConfig::BodyField { path } => InjectionTarget::body_field(path),
            InjectionTargetConfig::BasicAuth { username } => InjectionTarget::BasicAuth {
                username: username.clone(),
            },
        }
    }
}

// ============================================================================
// Security Gate Response — Tuck → Anaphase
// ============================================================================

/// Security gate response from Tuck to Anaphase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGateResponse {
    /// Echoes the trace_id from the request.
    pub trace_id: Uuid,
    /// Tuck decision.
    pub decision: GateDecision,
    /// Whether a credential was injected (only for Pass decisions).
    pub credential_injected: bool,
    /// Injected credential (only if injection_target is None and Pass).
    /// Anaphase must zeroize this after use.
    pub credential: Option<Vec<u8>>,
    /// Audit entry ID (for traceability).
    pub audit_entry_id: Option<Uuid>,
    /// Human-readable reason (for Reject/HITL decisions).
    pub reason: Option<String>,
    /// Effective risk level (after Rule 6 downgrade if applicable).
    pub effective_risk_level: String,
}

/// Gate decision (mirrors Decision but with Anaphase-friendly naming).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    /// Pass — action may proceed.
    Pass,
    /// Reject — action is blocked by security policy.
    Reject,
    /// HITL required — action needs human confirmation (escalate to HITL gate).
    HitlRequired,
    /// Hard override — emergency pass (CATASTROPHIC + override flag).
    HardOverride,
}

impl From<Decision> for GateDecision {
    fn from(d: Decision) -> Self {
        match d {
            Decision::Pass => Self::Pass,
            Decision::Reject => Self::Reject,
            Decision::NeedHumanConfirm => Self::HitlRequired,
            Decision::HardOverridePass => Self::HardOverride,
        }
    }
}

impl From<SapDecision> for GateDecision {
    fn from(d: SapDecision) -> Self {
        match d {
            SapDecision::Pass => Self::Pass,
            SapDecision::Reject { .. } => Self::Reject,
            SapDecision::NeedHumanConfirm => Self::HitlRequired,
            SapDecision::HardOverridePass => Self::HardOverride,
        }
    }
}

// ============================================================================
// TuckSecurityGate — the security gate implementation
// ============================================================================

/// Tuck security gate — the core implementation of gate #3 in Anaphase's
/// three-gate model (tool audit → HITL → Tuck).
///
/// This struct encapsulates the full security gate flow:
/// 1. Parse PFP (and optional SAP)
/// 2. Make hard real-time decision (with SAP enhancement if present)
/// 3. If Pass and identity_label present, inject credential
/// 4. Write audit log entry
/// 5. Return structured response
pub struct TuckSecurityGate<S: CredentialStore> {
    /// Security policy (risk level → decision mapping).
    policy: SecurityPolicy,
    /// Credential store (for resolving identity_label → plaintext credential).
    credential_store: S,
    /// Audit log (for recording all decisions).
    audit_log: AuditLog,
    /// Replay cache (for SAP replay protection).
    replay_cache: LruReplayCache,
    /// Optional signature verifier (for SAP PAH-Signature verification).
    signature_verifier: Option<Box<dyn SignatureVerifier>>,
    /// Source ID for audit logging.
    source_id: String,
}

impl<S: CredentialStore> TuckSecurityGate<S> {
    /// Create a new security gate.
    pub fn new(
        policy: SecurityPolicy,
        credential_store: S,
        source_id: impl Into<String>,
    ) -> Self {
        Self {
            policy,
            credential_store,
            audit_log: AuditLog::new(),
            replay_cache: LruReplayCache::new(),
            signature_verifier: None,
            source_id: source_id.into(),
        }
    }

    /// Set the signature verifier for SAP PAH-Signature verification.
    pub fn with_signature_verifier(mut self, verifier: Box<dyn SignatureVerifier>) -> Self {
        self.signature_verifier = Some(verifier);
        self
    }

    /// Set the replay cache capacity.
    pub fn with_replay_capacity(mut self, capacity: usize) -> Self {
        self.replay_cache = LruReplayCache::with_capacity(capacity);
        self
    }

    /// Process a security gate request.
    ///
    /// This is the main entry point for Anaphase → Tuck security gate checks.
    pub async fn process(&mut self, request: &SecurityGateRequest) -> SecurityGateResponse {
        let trace_id = request.trace_id;

        // Step 1: Parse PFP
        let pfp = match PfpHeader::from_bytes(request.pfp) {
            Ok(pfp) => pfp,
            Err(e) => {
                // Invalid PFP → fail-closed (Reject)
                let reason = format!("Invalid PFP: {e}");
                self.log_audit(
                    Decision::Reject,
                    &pfp_effective_risk_str(&request.pfp),
                    &request.action_description,
                    request.identity_label.as_deref(),
                );
                return SecurityGateResponse {
                    trace_id,
                    decision: GateDecision::Reject,
                    credential_injected: false,
                    credential: None,
                    audit_entry_id: None,
                    reason: Some(reason),
                    effective_risk_level: "Unknown".to_string(),
                };
            }
        };

        let effective_risk = format!("{:?}", pfp.effective_risk_level());

        // Step 2: Make decision (with SAP enhancement if present)
        let decision = if let Some(sap_bytes) = request.sap {
            // Parse SAP and use enhanced decision
            match SapHeader::from_bytes(sap_bytes) {
                Ok(sap) => {
                    let sap_decision = decide_with_sap(
                        &pfp,
                        Some(&sap),
                        &request.source_id,
                        &mut self.replay_cache,
                        self.signature_verifier.as_deref(),
                        &self.policy,
                    );
                    match sap_decision {
                        SapDecision::Pass => Decision::Pass,
                        SapDecision::Reject { .. } => Decision::Reject,
                        SapDecision::NeedHumanConfirm => Decision::NeedHumanConfirm,
                        SapDecision::HardOverridePass => Decision::HardOverridePass,
                    }
                }
                Err(_) => {
                    // Invalid SAP → fail-closed (Reject)
                    Decision::Reject
                }
            }
        } else {
            // No SAP → pure PFP decision (hard real-time)
            crate::decide(&pfp, &self.policy)
        };

        // Step 3: If Pass and identity_label present, inject credential
        let (credential_injected, credential) = if matches!(decision, Decision::Pass | Decision::HardOverridePass) {
            if let Some(label_str) = &request.identity_label {
                match IdentityLabel::parse(label_str) {
                    Ok(label) => {
                        match self.credential_store.get(&label).await {
                            Ok(cred) => {
                                if let Some(target_config) = &request.injection_target {
                                    // Inject into outbound request (Tuck-side injection)
                                    let target = InjectionTarget::from(target_config);
                                    let mut req = OutboundRequest::new();
                                    // Manual injection (InjectionEngine needs owned S, we have &S)
                                    let secret = cred.expose_secret();
                                    let result = match &target {
                                        InjectionTarget::HttpHeader { name } => {
                                            req.headers.insert(name.clone(), String::from_utf8_lossy(secret).to_string());
                                            true
                                        }
                                        InjectionTarget::BearerToken => {
                                            req.headers.insert("Authorization".to_string(), format!("Bearer {}", String::from_utf8_lossy(secret)));
                                            true
                                        }
                                        InjectionTarget::QueryParam { name } => {
                                            req.query_params.insert(name.clone(), String::from_utf8_lossy(secret).to_string());
                                            true
                                        }
                                        _ => false, // BodyField/BasicAuth need more context
                                    };
                                    if result {
                                        (true, None)
                                    } else {
                                        (false, Some(secret.to_vec()))
                                    }
                                } else {
                                    // Return credential for Anaphase to inject
                                    (false, Some(cred.expose_secret().to_vec()))
                                }
                            }
                            Err(_) => (false, None), // Credential not found, but still Pass
                        }
                    }
                    Err(_) => (false, None), // Invalid label, but still Pass
                }
            } else {
                (false, None) // No identity_label
            }
        } else {
            (false, None) // Not Pass, no credential injection
        };

        // Step 4: Write audit log
        let audit_id = self.log_audit(
            decision,
            &effective_risk,
            &request.action_description,
            request.identity_label.as_deref(),
        );

        // Step 5: Return response
        let reason = match decision {
            Decision::Reject => Some("Security policy rejected this action".to_string()),
            Decision::NeedHumanConfirm => Some("Human confirmation required (HITL gate)".to_string()),
            _ => None,
        };

        SecurityGateResponse {
            trace_id,
            decision: GateDecision::from(decision),
            credential_injected,
            credential,
            audit_entry_id: audit_id,
            reason,
            effective_risk_level: effective_risk,
        }
    }

    /// Log an audit entry.
    fn log_audit(
        &mut self,
        decision: Decision,
        risk_level: &str,
        source: &str,
        identity_label: Option<&str>,
    ) -> Option<Uuid> {
        let entry = self.audit_log.append(
            decision,
            risk_level,
            "Executive", // modality
            "Normal",    // override flag
            source,
            identity_label,
        );
        Some(entry.entry_id)
    }

    /// Get a reference to the audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Get a reference to the security policy.
    pub fn policy(&self) -> &SecurityPolicy {
        &self.policy
    }
}

// ============================================================================
// AnaphaseBridge Trait — pluggable interaction with Anaphase
// ============================================================================

/// Trait for interacting with Anaphase orchestration layer.
///
/// Implementations handle the actual transport (gRPC, HTTP, in-process).
/// Tuck core only depends on this trait.
#[async_trait::async_trait]
pub trait AnaphaseBridge: Send + Sync {
    /// Send a security gate response to Anaphase.
    async fn send_gate_response(&self, response: &SecurityGateResponse) -> Result<(), BridgeError>;

    /// Request HITL confirmation from Anaphase (escalation to gate #2).
    async fn request_hitl_confirmation(&self, request: &SecurityGateRequest) -> Result<bool, BridgeError>;

    /// Check if the bridge is connected to Anaphase.
    async fn is_connected(&self) -> bool;
}

/// Bridge error.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// Connection to Anaphase failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Request timed out.
    #[error("request timed out")]
    Timeout,

    /// Anaphase returned an error.
    #[error("anaphase error: {0}")]
    AnaphaseError(String),
}

// ============================================================================
// NoopAnaphaseBridge — for testing or standalone deployments
// ============================================================================

/// No-op implementation of AnaphaseBridge.
#[derive(Debug, Clone, Default)]
pub struct NoopAnaphaseBridge;

#[async_trait::async_trait]
impl AnaphaseBridge for NoopAnaphaseBridge {
    async fn send_gate_response(&self, _response: &SecurityGateResponse) -> Result<(), BridgeError> {
        Ok(())
    }

    async fn request_hitl_confirmation(&self, _request: &SecurityGateRequest) -> Result<bool, BridgeError> {
        Err(BridgeError::ConnectionFailed(
            "NoopAnaphaseBridge does not support HITL confirmation".to_string(),
        ))
    }

    async fn is_connected(&self) -> bool {
        false
    }
}

// ============================================================================
// Helper
// ============================================================================

fn pfp_effective_risk_str(bytes: &[u8; 4]) -> String {
    if let Ok(pfp) = PfpHeader::from_bytes(*bytes) {
        format!("{:?}", pfp.effective_risk_level())
    } else {
        "Unknown".to_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::InMemoryCredentialStore;
    use crate::{Modality, OutputDest, ReplayEnable};

    fn make_pfp_bytes(risk: RiskLevel, override_flag: OverrideFlag) -> [u8; 4] {
        let mut bytes = [0xCF, 0x14, 0, 0];
        bytes[2] = (Modality::Executive as u8) | (risk as u8) << 2;
        bytes[3] = (OutputDest::External as u8) | (override_flag as u8) << 1 | (ReplayEnable::Enabled as u8) << 2;
        bytes
    }

    fn make_request(pfp: [u8; 4], identity_label: Option<&str>) -> SecurityGateRequest {
        SecurityGateRequest {
            trace_id: Uuid::new_v4(),
            source_id: "anaphase_test".to_string(),
            pfp,
            sap: None,
            identity_label: identity_label.map(|s| s.to_string()),
            action_type: "executive".to_string(),
            action_description: "test action".to_string(),
            injection_target: None,
        }
    }

    #[tokio::test]
    async fn test_security_gate_pass() {
        let store = InMemoryCredentialStore::new();
        let policy = SecurityPolicy::default();
        let mut gate = TuckSecurityGate::new(policy, store, "tuck_test");

        let pfp = make_pfp_bytes(RiskLevel::Low, OverrideFlag::Normal);
        let request = make_request(pfp, None);
        let response = gate.process(&request).await;

        assert_eq!(response.decision, GateDecision::Pass);
        assert!(!response.credential_injected);
        assert!(response.credential.is_none());
        assert!(response.audit_entry_id.is_some());
        assert_eq!(response.effective_risk_level, "Low");
    }

    #[tokio::test]
    async fn test_security_gate_reject() {
        let store = InMemoryCredentialStore::new();
        let policy = SecurityPolicy::default();
        let mut gate = TuckSecurityGate::new(policy, store, "tuck_test");

        // Catastrophic without override → Reject
        let pfp = make_pfp_bytes(RiskLevel::Catastrophic, OverrideFlag::Normal);
        let request = make_request(pfp, None);
        let response = gate.process(&request).await;

        assert_eq!(response.decision, GateDecision::Reject);
        assert!(response.reason.is_some());
        assert!(response.audit_entry_id.is_some());
    }

    #[tokio::test]
    async fn test_security_gate_hitl_required() {
        let store = InMemoryCredentialStore::new();
        let policy = SecurityPolicy {
            critical: Decision::NeedHumanConfirm,
            ..Default::default()
        };
        let mut gate = TuckSecurityGate::new(policy, store, "tuck_test");

        let pfp = make_pfp_bytes(RiskLevel::Critical, OverrideFlag::Normal);
        let request = make_request(pfp, None);
        let response = gate.process(&request).await;

        assert_eq!(response.decision, GateDecision::HitlRequired);
        assert!(response.reason.is_some());
    }

    #[tokio::test]
    async fn test_security_gate_hard_override() {
        let store = InMemoryCredentialStore::new();
        let policy = SecurityPolicy::default();
        let mut gate = TuckSecurityGate::new(policy, store, "tuck_test");

        // Catastrophic with override → HardOverride
        let pfp = make_pfp_bytes(RiskLevel::Catastrophic, OverrideFlag::HardOverride);
        let request = make_request(pfp, None);
        let response = gate.process(&request).await;

        assert_eq!(response.decision, GateDecision::HardOverride);
        assert!(response.audit_entry_id.is_some());
    }

    #[tokio::test]
    async fn test_security_gate_invalid_pfp() {
        let store = InMemoryCredentialStore::new();
        let policy = SecurityPolicy::default();
        let mut gate = TuckSecurityGate::new(policy, store, "tuck_test");

        // Invalid magic → fail-closed (Reject)
        let pfp = [0x00, 0x00, 0x00, 0x00];
        let request = make_request(pfp, None);
        let response = gate.process(&request).await;

        assert_eq!(response.decision, GateDecision::Reject);
        assert!(response.reason.is_some());
        assert!(response.reason.unwrap().contains("Invalid PFP"));
    }

    #[tokio::test]
    async fn test_security_gate_with_credential() {
        let store = InMemoryCredentialStore::new();
        store.insert("env:test/key", b"secret-credential");
        let policy = SecurityPolicy::default();
        let mut gate = TuckSecurityGate::new(policy, store, "tuck_test");

        let pfp = make_pfp_bytes(RiskLevel::Low, OverrideFlag::Normal);
        let request = make_request(pfp, Some("env:test/key"));
        let response = gate.process(&request).await;

        assert_eq!(response.decision, GateDecision::Pass);
        // Credential returned for Anaphase to inject (no injection_target specified)
        assert!(response.credential.is_some());
        assert_eq!(response.credential.unwrap(), b"secret-credential");
    }

    #[tokio::test]
    async fn test_security_gate_audit_log() {
        let store = InMemoryCredentialStore::new();
        let policy = SecurityPolicy::default();
        let mut gate = TuckSecurityGate::new(policy, store, "tuck_test");

        let pfp1 = make_pfp_bytes(RiskLevel::Low, OverrideFlag::Normal);
        let pfp2 = make_pfp_bytes(RiskLevel::Catastrophic, OverrideFlag::Normal);

        let req1 = make_request(pfp1, None);
        let req2 = make_request(pfp2, None);

        gate.process(&req1).await;
        gate.process(&req2).await;

        // Both decisions should be logged
        assert_eq!(gate.audit_log().len(), 2);
        assert!(gate.audit_log().verify_chain().is_ok());
    }

    #[test]
    fn test_gate_decision_from_decision() {
        assert_eq!(GateDecision::from(Decision::Pass), GateDecision::Pass);
        assert_eq!(GateDecision::from(Decision::Reject), GateDecision::Reject);
        assert_eq!(GateDecision::from(Decision::NeedHumanConfirm), GateDecision::HitlRequired);
        assert_eq!(GateDecision::from(Decision::HardOverridePass), GateDecision::HardOverride);
    }

    #[test]
    fn test_security_gate_request_serialization() {
        let pfp = make_pfp_bytes(RiskLevel::Low, OverrideFlag::Normal);
        let request = make_request(pfp, Some("env:test/key"));
        let json = serde_json::to_string(&request).unwrap();
        let parsed: SecurityGateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action_type, "executive");
        assert_eq!(parsed.identity_label, Some("env:test/key".to_string()));
    }

    #[test]
    fn test_injection_target_config_conversion() {
        let config = InjectionTargetConfig::HttpHeader { name: "X-API-Key".to_string() };
        let target = InjectionTarget::from(&config);
        match target {
            InjectionTarget::HttpHeader { name } => assert_eq!(name, "X-API-Key"),
            _ => panic!("expected HttpHeader"),
        }
    }

    #[tokio::test]
    async fn test_noop_anaphase_bridge() {
        let bridge = NoopAnaphaseBridge;
        assert!(!bridge.is_connected().await);

        let response = SecurityGateResponse {
            trace_id: Uuid::new_v4(),
            decision: GateDecision::Pass,
            credential_injected: false,
            credential: None,
            audit_entry_id: None,
            reason: None,
            effective_risk_level: "Low".to_string(),
        };
        assert!(bridge.send_gate_response(&response).await.is_ok());
        assert!(bridge.request_hitl_confirmation(&make_request([0xCF, 0x14, 0, 0], None)).await.is_err());
    }
}
