//! Tuck ↔ Helix-Mind interaction bridge.
//!
//! # Design Principle
//!
//! **极致解耦**: Tuck does NOT depend on helix-mind-core directly. This module
//! defines Tuck-side types and traits for interacting with Helix-Mind. The
//! actual transport (IntentEnvelope conversion, gRPC, HTTP, etc.) is handled
//! by an adapter layer in the deployment environment.
//!
//! **按需驱动**: Security events are sent only when Tuck makes a non-Pass
//! decision (Reject/HITL/CATASTROPHIC). Pass decisions are not notified to
//! avoid noise — Mind only needs to know when something is blocked or needs
//! human attention.
//!
//! **物理事实优先**: The PFP risk label is the physical fact that flows from
//! Mind's intent to Tuck's decision. Mind constructs the PFP based on the
//! nature of the action (cognitive/render/executive/sensor_feed + risk level),
//! and Tuck makes the hard real-time decision based on that physical fact.
//!
//! # Interaction Model
//!
//! ```text
//! Helix-Mind (cognitive craft)
//!   │
//!   │ 1. IntentEnvelope with PFP risk label (physical fact)
//!   ▼
//! Anaphase (orchestration)
//!   │
//!   │ 2. Forward to Tentacle with PFP + identity_label
//!   ▼
//! Tuck (security gate)
//!   │
//!   │ 3. Hard real-time decide() (sub-μs, reads 4-byte PFP)
//!   │
//!   ├─ Pass → continue to Tentacle
//!   ├─ Reject → send SecurityEvent to Mind (async)
//!   ├─ NeedHumanConfirm → send SecurityEvent to Mind (async)
//!   └─ HardOverridePass → send SecurityEvent to Mind (async, emergency)
//!   │
//!   │ 4. Mind queries Tuck audit log (on-demand, for post-hoc analysis)
//!   ▼
//! Helix-Mind (security posture awareness)
//! ```

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Decision, OverrideFlag, RiskLevel};
use crate::audit_query::{AuditQuery, QueryResult};

// ============================================================================
// Security Event — Tuck → Helix-Mind
// ============================================================================

/// Security event sent from Tuck to Helix-Mind when a non-Pass decision is made.
///
/// This is the Tuck-side representation. The deployment adapter converts this
/// into a Helix-Mind `IntentEnvelope` with `intent_type = "TUCK_SecurityEvent"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Globally unique event ID (for trace correlation).
    pub event_id: Uuid,
    /// Trace ID from the original request (end-to-end observability).
    pub trace_id: Uuid,
    /// Source identifier (e.g., "tuck_gateway_01").
    pub source_id: String,
    /// Tuck decision that triggered this event.
    pub decision: SecurityDecision,
    /// Risk level from the PFP header (string representation for serialization).
    pub risk_level: String,
    /// Override flag from the PFP header (string representation for serialization).
    pub override_flag: String,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Timestamp (unix epoch seconds).
    pub timestamp: u64,
    /// Optional identity_label involved (if credential injection was attempted).
    pub identity_label: Option<String>,
}

/// Security decision type (mirrors `Decision` but with event-friendly naming).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityDecision {
    /// Request rejected by security policy.
    Rejected,
    /// Request needs human confirmation (HITL gate).
    NeedHumanConfirm,
    /// Emergency hard override pass (CATASTROPHIC + override flag).
    HardOverridePass,
}

impl From<Decision> for SecurityDecision {
    fn from(d: Decision) -> Self {
        match d {
            Decision::Reject => Self::Rejected,
            Decision::NeedHumanConfirm => Self::NeedHumanConfirm,
            Decision::HardOverridePass => Self::HardOverridePass,
            Decision::Pass => {
                // Pass should not trigger a security event, but if it does,
                // treat as Rejected (should never happen in practice).
                Self::Rejected
            }
        }
    }
}

impl SecurityEvent {
    /// Create a new security event from a Tuck decision.
    ///
    /// Returns `None` if the decision is `Pass` (no event needed).
    pub fn from_decision(
        decision: Decision,
        trace_id: Uuid,
        source_id: impl Into<String>,
        risk_level: RiskLevel,
        override_flag: OverrideFlag,
        reason: impl Into<String>,
        identity_label: Option<String>,
    ) -> Option<Self> {
        if matches!(decision, Decision::Pass) {
            return None; // Pass decisions don't generate events
        }

        Some(Self {
            event_id: Uuid::new_v4(),
            trace_id,
            source_id: source_id.into(),
            decision: SecurityDecision::from(decision),
            risk_level: format!("{:?}", risk_level),
            override_flag: format!("{:?}", override_flag),
            reason: reason.into(),
            timestamp: current_timestamp(),
            identity_label,
        })
    }

    /// Check if this event is an emergency (CATASTROPHIC + hard override).
    pub fn is_emergency(&self) -> bool {
        matches!(self.decision, SecurityDecision::HardOverridePass)
    }

    /// Check if this event requires human attention.
    pub fn needs_human_attention(&self) -> bool {
        matches!(self.decision, SecurityDecision::NeedHumanConfirm)
            || self.is_emergency()
    }

    /// Convert to IntentEnvelope-compatible JSON payload.
    ///
    /// The deployment adapter uses this to construct a Helix-Mind IntentEnvelope.
    pub fn to_intent_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "event_id": self.event_id.to_string(),
            "trace_id": self.trace_id.to_string(),
            "source_id": self.source_id,
            "decision": self.decision,
            "risk_level": format!("{:?}", self.risk_level),
            "override_flag": format!("{:?}", self.override_flag),
            "reason": self.reason,
            "timestamp": self.timestamp,
            "identity_label": self.identity_label,
        })
    }
}

// ============================================================================
// Audit Query — Helix-Mind → Tuck
// ============================================================================

/// Audit query request from Helix-Mind to Tuck.
///
/// Mind can query Tuck's audit log for post-hoc security analysis,
/// incident investigation, or security posture awareness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQueryRequest {
    /// Trace ID for observability.
    pub trace_id: Uuid,
    /// Source identifier (e.g., "helix_mind_security_analyzer").
    pub source_id: String,
    /// The audit query parameters.
    pub query: AuditQuery,
}

/// Audit query response from Tuck to Helix-Mind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQueryResponse {
    /// Echoes the trace_id from the request.
    pub trace_id: Uuid,
    /// Whether the query was successful.
    pub success: bool,
    /// Query result (paginated entries).
    pub result: Option<QueryResult>,
    /// Error description if `success` is false.
    pub error: Option<String>,
}

// ============================================================================
// PFP Construction Helper — for Helix-Mind cognitive craft
// ============================================================================

/// Action type classification for PFP construction.
///
/// Helix-Mind's cognitive craft uses this to determine the PFP risk label
/// when initiating an action that goes through Tuck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    /// Pure cognitive operation (thinking, reasoning, memory retrieval).
    /// Low risk, no physical effect.
    Cognitive,
    /// Render operation (text generation, image generation, speech synthesis).
    /// Medium risk, output goes to user.
    Render,
    /// Executive operation (tool call, API call, physical action).
    /// High risk, affects external systems or physical world.
    Executive,
    /// Sensor feed operation (camera, microphone, tactile, IMU).
    /// Variable risk, depends on sensor type and data sensitivity.
    SensorFeed,
}

impl ActionType {
    /// Get the default risk level for this action type.
    ///
    /// This is a starting point — the actual risk level may be adjusted
    /// based on specific action parameters (e.g., financial transaction = CRITICAL).
    pub fn default_risk(&self) -> RiskLevel {
        match self {
            Self::Cognitive => RiskLevel::Low,
            Self::Render => RiskLevel::Medium,
            Self::Executive => RiskLevel::Critical,
            Self::SensorFeed => RiskLevel::Medium,
        }
    }

    /// Check if this action type requires Tuck security gate.
    ///
    /// Cognitive operations don't need Tuck (they don't leave Mind).
    /// All other types must go through Tuck.
    pub fn requires_security_gate(&self) -> bool {
        !matches!(self, Self::Cognitive)
    }
}

impl From<ActionType> for crate::Modality {
    fn from(action: ActionType) -> Self {
        match action {
            ActionType::Cognitive => crate::Modality::Cognitive,
            ActionType::Render => crate::Modality::Render,
            ActionType::Executive => crate::Modality::Executive,
            ActionType::SensorFeed => crate::Modality::SensorFeed,
        }
    }
}

/// PFP construction guidance for Helix-Mind cognitive craft.
///
/// This struct provides a structured way for Mind to construct the 4-byte PFP
/// header when initiating an action. Mind fills in the physical facts (modality,
/// risk level, body stance, proximity edge), and Tuck makes the hard real-time
/// decision based on those facts.
#[derive(Debug, Clone)]
pub struct PfpConstructionGuide {
    /// The type of action being initiated.
    pub action_type: ActionType,
    /// Risk level (Mind's assessment, may be higher than default).
    pub risk_level: RiskLevel,
    /// Whether this is an external output (leaves the local system).
    pub external_output: bool,
    /// Whether hard override is requested (emergency only).
    pub hard_override: bool,
    /// Whether replay protection is enabled (default: true).
    pub replay_enabled: bool,
}

impl PfpConstructionGuide {
    /// Create a new construction guide with sensible defaults.
    pub fn new(action_type: ActionType) -> Self {
        Self {
            action_type,
            risk_level: action_type.default_risk(),
            external_output: !matches!(action_type, ActionType::Cognitive),
            hard_override: false,
            replay_enabled: true,
        }
    }

    /// Escalate the risk level (e.g., financial transaction → CRITICAL).
    pub fn escalate_risk(mut self, risk: RiskLevel) -> Self {
        self.risk_level = risk;
        self
    }

    /// Mark as emergency hard override.
    pub fn emergency_override(mut self) -> Self {
        self.hard_override = true;
        self.risk_level = RiskLevel::Catastrophic;
        self
    }

    /// Build the 4-byte PFP header.
    pub fn build_pfp(&self) -> crate::PfpHeader {
        let modality = crate::Modality::from(self.action_type);
        let body_stance = crate::BodyStance::Unknown; // Mind doesn't know physical stance
        let proximity_edge = crate::ProximityEdge::Safe; // Default safe
        let output_dest = if self.external_output {
            crate::OutputDest::External
        } else {
            crate::OutputDest::Internal
        };
        let override_flag = if self.hard_override {
            OverrideFlag::HardOverride
        } else {
            OverrideFlag::Normal
        };
        let replay_enable = if self.replay_enabled {
            crate::ReplayEnable::Enabled
        } else {
            crate::ReplayEnable::Disabled
        };

        let mut bytes = [0u8; 4];
        bytes[0] = 0xCF;
        bytes[1] = 0x14;
        bytes[2] = (modality as u8)
            | (self.risk_level as u8) << 2
            | (body_stance as u8) << 4
            | (proximity_edge as u8) << 6;
        bytes[3] = (output_dest as u8)
            | (override_flag as u8) << 1
            | (replay_enable as u8) << 2;

        crate::PfpHeader::from_bytes(bytes).expect("PFP construction guide always produces valid PFP")
    }
}

// ============================================================================
// MindBridge Trait — pluggable interaction with Helix-Mind
// ============================================================================

/// Trait for interacting with Helix-Mind.
///
/// Implementations handle the actual transport (IntentEnvelope over gRPC,
/// HTTP, message queue, etc.). Tuck core only depends on this trait.
///
/// This follows the "极致解耦" principle: Tuck doesn't know how Mind receives
/// events, it just calls `send_security_event()` and the implementation handles
/// the rest.
#[async_trait::async_trait]
pub trait MindBridge: Send + Sync {
    /// Send a security event to Helix-Mind.
    ///
    /// This is called asynchronously after Tuck makes a non-Pass decision.
    /// It should NOT block the hard real-time decision path.
    async fn send_security_event(&self, event: &SecurityEvent) -> Result<(), MindBridgeError>;

    /// Query Tuck's audit log on behalf of Helix-Mind.
    ///
    /// Mind calls this for post-hoc security analysis or incident investigation.
    async fn query_audit(&self, request: &AuditQueryRequest) -> Result<AuditQueryResponse, MindBridgeError>;

    /// Check if the bridge is connected to Helix-Mind.
    async fn is_connected(&self) -> bool;
}

/// MindBridge error.
#[derive(Debug, thiserror::Error)]
pub enum MindBridgeError {
    /// Connection to Helix-Mind failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Request timed out.
    #[error("request timed out")]
    Timeout,

    /// Helix-Mind returned an error.
    #[error("mind error: {0}")]
    MindError(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ============================================================================
// NoopMindBridge — for testing or deployments without Helix-Mind
// ============================================================================

/// No-op implementation of MindBridge that discards all events.
///
/// Used in testing or in deployments where Tuck runs standalone without
/// Helix-Mind integration.
#[derive(Debug, Clone, Default)]
pub struct NoopMindBridge;

#[async_trait::async_trait]
impl MindBridge for NoopMindBridge {
    async fn send_security_event(&self, _event: &SecurityEvent) -> Result<(), MindBridgeError> {
        Ok(()) // Discard
    }

    async fn query_audit(&self, _request: &AuditQueryRequest) -> Result<AuditQueryResponse, MindBridgeError> {
        Err(MindBridgeError::ConnectionFailed(
            "NoopMindBridge does not support audit queries".to_string(),
        ))
    }

    async fn is_connected(&self) -> bool {
        false
    }
}

// ============================================================================
// SecurityEventEmitter — convenience wrapper for emitting events
// ============================================================================

/// Security event emitter — wraps a MindBridge and provides convenience methods
/// for emitting security events from Tuck decisions.
#[derive(Clone)]
pub struct SecurityEventEmitter {
    bridge: std::sync::Arc<dyn MindBridge>,
    source_id: String,
}

impl std::fmt::Debug for SecurityEventEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The bridge is a trait object — print its identity only, never
        // its internals (memory hygiene: no payload in logs).
        f.debug_struct("SecurityEventEmitter")
            .field("source_id", &self.source_id)
            .finish_non_exhaustive()
    }
}

impl SecurityEventEmitter {
    /// Create a new event emitter with the given bridge and source ID.
    pub fn new(bridge: std::sync::Arc<dyn MindBridge>, source_id: impl Into<String>) -> Self {
        Self {
            bridge,
            source_id: source_id.into(),
        }
    }

    /// Emit a security event for a Tuck decision (if non-Pass).
    ///
    /// Returns `true` if an event was emitted, `false` if the decision was Pass.
    pub async fn emit_for_decision(
        &self,
        decision: Decision,
        trace_id: Uuid,
        risk_level: RiskLevel,
        override_flag: OverrideFlag,
        reason: impl Into<String>,
        identity_label: Option<String>,
    ) -> bool {
        let Some(event) = SecurityEvent::from_decision(
            decision,
            trace_id,
            &self.source_id,
            risk_level,
            override_flag,
            reason,
            identity_label,
        ) else {
            return false; // Pass decision, no event
        };

        // Fire and forget — don't block on bridge errors
        if let Err(e) = self.bridge.send_security_event(&event).await {
            eprintln!("[Tuck] Failed to send security event to Mind: {e}");
        }
        true
    }

    /// Check if the bridge is connected.
    pub async fn is_connected(&self) -> bool {
        self.bridge.is_connected().await
    }
}

// ============================================================================
// Helper
// ============================================================================

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_from_pass_decision() {
        let event = SecurityEvent::from_decision(
            Decision::Pass,
            Uuid::new_v4(),
            "tuck_01",
            RiskLevel::Low,
            OverrideFlag::Normal,
            "test",
            None,
        );
        assert!(event.is_none()); // Pass doesn't generate event
    }

    #[test]
    fn test_security_event_from_reject_decision() {
        let trace_id = Uuid::new_v4();
        let event = SecurityEvent::from_decision(
            Decision::Reject,
            trace_id,
            "tuck_01",
            RiskLevel::Critical,
            OverrideFlag::Normal,
            "policy rejected",
            Some("env:test/key".to_string()),
        )
        .unwrap();

        assert_eq!(event.decision, SecurityDecision::Rejected);
        assert_eq!(event.trace_id, trace_id);
        assert_eq!(event.risk_level, "Critical");
        assert!(event.identity_label.is_some());
        assert!(!event.is_emergency());
        assert!(!event.needs_human_attention());
    }

    #[test]
    fn test_security_event_from_hitl_decision() {
        let event = SecurityEvent::from_decision(
            Decision::NeedHumanConfirm,
            Uuid::new_v4(),
            "tuck_01",
            RiskLevel::Critical,
            OverrideFlag::Normal,
            "needs human confirm",
            None,
        )
        .unwrap();

        assert_eq!(event.decision, SecurityDecision::NeedHumanConfirm);
        assert!(event.needs_human_attention());
    }

    #[test]
    fn test_security_event_from_hard_override() {
        let event = SecurityEvent::from_decision(
            Decision::HardOverridePass,
            Uuid::new_v4(),
            "tuck_01",
            RiskLevel::Catastrophic,
            OverrideFlag::HardOverride,
            "emergency override",
            None,
        )
        .unwrap();

        assert_eq!(event.decision, SecurityDecision::HardOverridePass);
        assert!(event.is_emergency());
        assert!(event.needs_human_attention());
    }

    #[test]
    fn test_security_event_to_intent_payload() {
        let event = SecurityEvent::from_decision(
            Decision::Reject,
            Uuid::new_v4(),
            "tuck_01",
            RiskLevel::Critical,
            OverrideFlag::Normal,
            "test reason",
            None,
        )
        .unwrap();

        let payload = event.to_intent_payload();
        assert_eq!(payload["decision"], "rejected");
        assert_eq!(payload["reason"], "test reason");
        assert!(payload["event_id"].is_string());
    }

    #[test]
    fn test_action_type_default_risk() {
        assert_eq!(ActionType::Cognitive.default_risk(), RiskLevel::Low);
        assert_eq!(ActionType::Render.default_risk(), RiskLevel::Medium);
        assert_eq!(ActionType::Executive.default_risk(), RiskLevel::Critical);
        assert_eq!(ActionType::SensorFeed.default_risk(), RiskLevel::Medium);
    }

    #[test]
    fn test_action_type_requires_security_gate() {
        assert!(!ActionType::Cognitive.requires_security_gate());
        assert!(ActionType::Render.requires_security_gate());
        assert!(ActionType::Executive.requires_security_gate());
        assert!(ActionType::SensorFeed.requires_security_gate());
    }

    #[test]
    fn test_pfp_construction_guide_basic() {
        let guide = PfpConstructionGuide::new(ActionType::Executive);
        assert_eq!(guide.risk_level, RiskLevel::Critical);
        assert!(guide.external_output);
        assert!(!guide.hard_override);
        assert!(guide.replay_enabled);

        let pfp = guide.build_pfp();
        assert_eq!(pfp.modality(), crate::Modality::Executive);
        assert_eq!(pfp.risk_level(), RiskLevel::Critical);
        assert_eq!(pfp.output_dest(), crate::OutputDest::External);
        assert_eq!(pfp.override_flag(), OverrideFlag::Normal);
        assert_eq!(pfp.replay_enable(), crate::ReplayEnable::Enabled);
    }

    #[test]
    fn test_pfp_construction_guide_escalate() {
        let guide = PfpConstructionGuide::new(ActionType::Executive)
            .escalate_risk(RiskLevel::Catastrophic);
        let pfp = guide.build_pfp();
        assert_eq!(pfp.risk_level(), RiskLevel::Catastrophic);
    }

    #[test]
    fn test_pfp_construction_guide_emergency() {
        let guide = PfpConstructionGuide::new(ActionType::Executive)
            .emergency_override();
        let pfp = guide.build_pfp();
        assert_eq!(pfp.risk_level(), RiskLevel::Catastrophic);
        assert_eq!(pfp.override_flag(), OverrideFlag::HardOverride);
    }

    #[test]
    fn test_pfp_construction_guide_cognitive() {
        let guide = PfpConstructionGuide::new(ActionType::Cognitive);
        assert!(!guide.external_output);
        let pfp = guide.build_pfp();
        assert_eq!(pfp.modality(), crate::Modality::Cognitive);
        assert_eq!(pfp.output_dest(), crate::OutputDest::Internal);
    }

    #[tokio::test]
    async fn test_noop_mind_bridge() {
        let bridge = NoopMindBridge;
        assert!(!bridge.is_connected().await);

        let event = SecurityEvent::from_decision(
            Decision::Reject,
            Uuid::new_v4(),
            "test",
            RiskLevel::Critical,
            OverrideFlag::Normal,
            "test",
            None,
        )
        .unwrap();
        assert!(bridge.send_security_event(&event).await.is_ok());

        let request = AuditQueryRequest {
            trace_id: Uuid::new_v4(),
            source_id: "test".to_string(),
            query: AuditQuery::default(),
        };
        assert!(bridge.query_audit(&request).await.is_err());
    }

    #[tokio::test]
    async fn test_security_event_emitter_pass() {
        let bridge = std::sync::Arc::new(NoopMindBridge);
        let emitter = SecurityEventEmitter::new(bridge, "tuck_test");

        let emitted = emitter
            .emit_for_decision(
                Decision::Pass,
                Uuid::new_v4(),
                RiskLevel::Low,
                OverrideFlag::Normal,
                "pass",
                None,
            )
            .await;
        assert!(!emitted); // Pass doesn't emit
    }

    #[tokio::test]
    async fn test_security_event_emitter_reject() {
        let bridge = std::sync::Arc::new(NoopMindBridge);
        let emitter = SecurityEventEmitter::new(bridge, "tuck_test");

        let emitted = emitter
            .emit_for_decision(
                Decision::Reject,
                Uuid::new_v4(),
                RiskLevel::Critical,
                OverrideFlag::Normal,
                "rejected by policy",
                None,
            )
            .await;
        assert!(emitted); // Reject emits event
    }

    #[test]
    fn test_audit_query_request_serialization() {
        let request = AuditQueryRequest {
            trace_id: Uuid::new_v4(),
            source_id: "mind_01".to_string(),
            query: AuditQuery::default().with_pagination(0, 50),
        };
        let json = serde_json::to_string(&request).unwrap();
        let parsed: AuditQueryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source_id, "mind_01");
    }
}