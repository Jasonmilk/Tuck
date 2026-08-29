//! Tuck ↔ Helix-Tentacle interaction bridge.
//!
//! # Design Principle
//!
//! **极致解耦**: Tuck does NOT depend on helix-tentacle directly. This module
//! defines Tuck-side types and traits for interacting with Tentacle's plugin
//! system and tool execution layer.
//!
//! **三层闸门对齐**: Tentacle is the "hand" (tool execution) of Helix.
//! Before any tool executes, it must pass through Tuck's security gate.
//! This is gate #3 in Anaphase's three-gate model:
//! 1. Tool audit (入库门) — Tentacle plugin registry + Manifest integrity
//! 2. HITL (执行闸) — human confirmation for high-risk tools
//! 3. Tuck (边缘物理闸) — hard real-time security decision
//!
//! **按需驱动**: Tuck only audits a plugin when Tentacle requests it
//! (plugin load time). Tuck only checks a tool call when Tentacle requests
//! it (tool execution time). No proactive scanning or polling.
//!
//! # Interaction Model
//!
//! ```text
//! Tentacle (plugin system + tool execution)
//!   │
//!   │ 1. PluginAuditRequest { manifest, plugin_hash, source }
//!   ▼
//! Tuck (plugin security auditor)
//!   │
//!   │ 2. Audit plugin: integrity check + permission analysis + security level
//!   │
//!   ├─ Pass → plugin can be loaded
//!   ├─ Reject → plugin is blocked (malicious / excessive permissions)
//!   └─ NeedHumanConfirm → plugin needs human review (Critical security level)
//!   │
//!   │ 3. PluginAuditResponse { decision, audit_entry_id, constraints }
//!   ▼
//! Tentacle (load or reject plugin)
//!   │
//!   │ 4. ToolExecutionRequest { tool_name, args, identity_label, pfp }
//!   ▼
//! Tuck (tool execution gate)
//!   │
//!   │ 5. Hard real-time decide() (sub-μs, reads 4-byte PFP)
//!   │
//!   ├─ Pass → inject credential (if identity_label present) → allow execution
//!   ├─ Reject → block execution
//!   ├─ NeedHumanConfirm → escalate to HITL
//!   └─ HardOverridePass → emergency allow
//!   │
//!   │ 6. ToolExecutionResponse { decision, credential_injected, sandbox_constraints }
//!   ▼
//! Tentacle (execute or block tool)
//! ```

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Decision, OverrideFlag, PfpHeader, RiskLevel, SecurityPolicy};
use crate::audit::AuditLog;
use crate::credential::{CredentialStore, IdentityLabel};

// ============================================================================
// Plugin Security Audit — Tentacle → Tuck (plugin load time)
// ============================================================================

/// Plugin audit request from Tentacle to Tuck (sent at plugin load time).
///
/// Tentacle sends the plugin's Manifest and integrity hash for Tuck to
/// perform a security audit before the plugin is loaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginAuditRequest {
    /// Trace ID for end-to-end observability.
    pub trace_id: Uuid,
    /// Source identifier (e.g., "tentacle_plugin_loader_01").
    pub source_id: String,
    /// Plugin name (from Manifest).
    pub plugin_name: String,
    /// Plugin version (from Manifest).
    pub plugin_version: String,
    /// Plugin security level (Normal/Critical, from Manifest).
    pub security_level: PluginSecurityLevel,
    /// Plugin integrity hash (SHA-256 of the plugin binary, from Manifest).
    pub integrity_hash: String,
    /// Actual computed hash of the plugin binary (for integrity verification).
    pub computed_hash: String,
    /// Plugin permissions (network/filesystem/execute/memory/cpu, from Manifest).
    pub permissions: PluginPermissions,
    /// Plugin identity requirements (from Manifest).
    pub requires_identity: Option<PluginIdentityRequirement>,
    /// Plugin source (local directory / remote URL / registry).
    pub source: PluginSource,
}

/// Plugin security level (mirrors Tentacle's SecurityLevel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginSecurityLevel {
    /// Normal operations (read-only, low risk).
    Normal,
    /// Critical operations (write/network/credential use, needs HITL).
    Critical,
}

impl Default for PluginSecurityLevel {
    fn default() -> Self {
        Self::Normal
    }
}

/// Plugin permissions (mirrors Tentacle's Permission struct).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginPermissions {
    /// Allowed network destinations (empty = no network access).
    #[serde(default)]
    pub network: Vec<String>,
    /// Allowed filesystem paths (empty = no filesystem access).
    #[serde(default)]
    pub filesystem: Vec<String>,
    /// Whether the plugin can execute external commands.
    #[serde(default)]
    pub execute: bool,
    /// Maximum memory in MB (None = no limit).
    #[serde(default)]
    pub max_memory_mb: Option<u32>,
    /// Maximum CPU time in ms (None = no limit).
    #[serde(default)]
    pub max_cpu_time_ms: Option<u32>,
}

/// Plugin identity requirement (mirrors Tentacle's RequiresIdentity).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginIdentityRequirement {
    /// Identity type (e.g., "cookie", "token").
    #[serde(default)]
    pub identity_type: Option<String>,
    /// Target domain (e.g., "weibo.com").
    #[serde(default)]
    pub domain: Option<String>,
    /// Sensitive fields (for redaction in audit logs).
    #[serde(default)]
    pub sensitive_fields: Vec<String>,
}

/// Plugin source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PluginSource {
    /// Local directory plugin.
    Local { path: String },
    /// Remote URL plugin.
    Remote { url: String },
    /// Registry plugin.
    Registry { name: String, version: String },
}

// ============================================================================
// Plugin Audit Response — Tuck → Tentacle
// ============================================================================

/// Plugin audit response from Tuck to Tentacle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginAuditResponse {
    /// Echoes the trace_id from the request.
    pub trace_id: Uuid,
    /// Audit decision.
    pub decision: PluginAuditDecision,
    /// Audit entry ID (for traceability).
    pub audit_entry_id: Option<Uuid>,
    /// Human-readable reason (for Reject/NeedHumanConfirm decisions).
    pub reason: Option<String>,
    /// Sandbox constraints (enforced by Tentacle during plugin execution).
    pub sandbox_constraints: SandboxConstraints,
    /// Integrity verification result.
    pub integrity_verified: bool,
}

/// Plugin audit decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginAuditDecision {
    /// Plugin is safe to load.
    Pass,
    /// Plugin is blocked (malicious / excessive permissions / integrity failure).
    Reject,
    /// Plugin needs human review (Critical security level or unusual permissions).
    NeedHumanConfirm,
}

/// Sandbox constraints (enforced by Tentacle during plugin execution).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxConstraints {
    /// Maximum memory in MB.
    pub max_memory_mb: u32,
    /// Maximum CPU time in ms per call.
    pub max_cpu_time_ms: u32,
    /// Whether network access is allowed.
    pub network_allowed: bool,
    /// Allowed network destinations (empty = all allowed if network_allowed).
    pub allowed_network: Vec<String>,
    /// Whether filesystem access is allowed.
    pub filesystem_allowed: bool,
    /// Allowed filesystem paths.
    pub allowed_filesystem: Vec<String>,
    /// Whether external command execution is allowed.
    pub execute_allowed: bool,
    /// Whether the plugin runs in WASM sandbox.
    pub wasm_sandbox: bool,
    /// Whether the plugin runs in JS sandbox.
    pub js_sandbox: bool,
}

impl SandboxConstraints {
    /// Create strict constraints (maximum security).
    pub fn strict() -> Self {
        Self {
            max_memory_mb: 64,
            max_cpu_time_ms: 5000,
            network_allowed: false,
            allowed_network: vec![],
            filesystem_allowed: false,
            allowed_filesystem: vec![],
            execute_allowed: false,
            wasm_sandbox: true,
            js_sandbox: true,
        }
    }

    /// Create relaxed constraints (for trusted plugins).
    pub fn relaxed() -> Self {
        Self {
            max_memory_mb: 512,
            max_cpu_time_ms: 30000,
            network_allowed: true,
            allowed_network: vec![],
            filesystem_allowed: true,
            allowed_filesystem: vec![],
            execute_allowed: true,
            wasm_sandbox: false,
            js_sandbox: false,
        }
    }
}

// ============================================================================
// Tool Execution Gate — Tentacle → Tuck (tool execution time)
// ============================================================================

/// Tool execution request from Tentacle to Tuck (sent before tool execution).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecutionRequest {
    /// Trace ID for end-to-end observability.
    pub trace_id: Uuid,
    /// Source identifier.
    pub source_id: String,
    /// Tool name (plugin name + tool function).
    pub tool_name: String,
    /// Tool arguments (JSON-serialized).
    pub args: serde_json::Value,
    /// 4-byte PFP header (physical fact: modality, risk level, etc.).
    pub pfp: [u8; 4],
    /// Optional identity label for credential injection.
    pub identity_label: Option<String>,
    /// Plugin security level (from the plugin's Manifest).
    pub plugin_security_level: PluginSecurityLevel,
    /// Whether this tool call involves network access.
    pub involves_network: bool,
    /// Whether this tool call involves filesystem write.
    pub involves_filesystem_write: bool,
    /// Whether this tool call involves credential use.
    pub involves_credential: bool,
}

/// Tool execution response from Tuck to Tentacle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecutionResponse {
    /// Echoes the trace_id from the request.
    pub trace_id: Uuid,
    /// Gate decision.
    pub decision: ToolExecutionDecision,
    /// Whether a credential was injected.
    pub credential_injected: bool,
    /// Injected credential (only if no injection target specified).
    pub credential: Option<Vec<u8>>,
    /// Audit entry ID.
    pub audit_entry_id: Option<Uuid>,
    /// Human-readable reason (for Reject/HITL decisions).
    pub reason: Option<String>,
    /// Effective risk level (after Rule 6 downgrade).
    pub effective_risk_level: String,
    /// Sandbox constraints for this tool call.
    pub sandbox_constraints: SandboxConstraints,
}

/// Tool execution decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolExecutionDecision {
    /// Tool may execute.
    Pass,
    /// Tool is blocked.
    Reject,
    /// Tool needs human confirmation (HITL).
    NeedHumanConfirm,
    /// Emergency hard override pass.
    HardOverridePass,
}

impl From<Decision> for ToolExecutionDecision {
    fn from(d: Decision) -> Self {
        match d {
            Decision::Pass => Self::Pass,
            Decision::Reject => Self::Reject,
            Decision::NeedHumanConfirm => Self::NeedHumanConfirm,
            Decision::HardOverridePass => Self::HardOverridePass,
        }
    }
}

// ============================================================================
// TuckPluginAuditor — plugin security audit implementation
// ============================================================================

/// Tuck plugin auditor — audits Tentacle plugins before they are loaded.
///
/// This implements the "入库门" (gate #1) security audit:
/// 1. Integrity verification (SHA-256 hash match)
/// 2. Permission analysis (excessive permissions → Reject/HITL)
/// 3. Security level assessment (Critical → HITL)
/// 4. Sandbox constraint generation
pub struct TuckPluginAuditor {
    /// Audit log.
    audit_log: AuditLog,
    /// Source ID for audit logging.
    source_id: String,
    /// Whether to require HITL for Critical security level plugins.
    pub require_hitl_for_critical: bool,
    /// Maximum allowed memory for any plugin (MB).
    pub max_allowed_memory_mb: u32,
    /// Maximum allowed CPU time for any plugin (ms).
    pub max_allowed_cpu_ms: u32,
}

impl TuckPluginAuditor {
    /// Create a new plugin auditor.
    pub fn new(source_id: impl Into<String>) -> Self {
        Self {
            audit_log: AuditLog::new(),
            source_id: source_id.into(),
            require_hitl_for_critical: true,
            max_allowed_memory_mb: 1024,
            max_allowed_cpu_ms: 60000,
        }
    }

    /// Audit a plugin (called at plugin load time).
    pub fn audit_plugin(&mut self, request: &PluginAuditRequest) -> PluginAuditResponse {
        let trace_id = request.trace_id;

        // Step 1: Integrity verification
        let integrity_verified = request.integrity_hash == request.computed_hash;

        // Step 2: Permission analysis
        let (permission_decision, permission_reason) = self.analyze_permissions(&request.permissions);

        // Step 3: Security level assessment
        let security_decision = if request.security_level == PluginSecurityLevel::Critical
            && self.require_hitl_for_critical
        {
            PluginAuditDecision::NeedHumanConfirm
        } else {
            PluginAuditDecision::Pass
        };

        // Step 4: Combine decisions (most restrictive wins)
        let decision = if !integrity_verified {
            PluginAuditDecision::Reject
        } else if permission_decision == PluginAuditDecision::Reject {
            PluginAuditDecision::Reject
        } else if permission_decision == PluginAuditDecision::NeedHumanConfirm
            || security_decision == PluginAuditDecision::NeedHumanConfirm
        {
            PluginAuditDecision::NeedHumanConfirm
        } else {
            PluginAuditDecision::Pass
        };

        // Step 5: Generate sandbox constraints
        let sandbox_constraints = self.generate_constraints(&request.permissions, request.security_level);

        // Step 6: Build reason
        let reason = if !integrity_verified {
            Some("Integrity verification failed: manifest hash does not match computed hash".to_string())
        } else if permission_decision == PluginAuditDecision::Reject {
            permission_reason
        } else if decision == PluginAuditDecision::NeedHumanConfirm {
            // Prefer specific permission reason over generic message
            permission_reason.or_else(|| {
                Some("Plugin requires human review (Critical security level or unusual permissions)".to_string())
            })
        } else {
            None
        };

        // Step 7: Log audit
        let audit_id = self.log_audit(
            decision,
            &request.plugin_name,
            &request.plugin_version,
            integrity_verified,
        );

        PluginAuditResponse {
            trace_id,
            decision,
            audit_entry_id: audit_id,
            reason,
            sandbox_constraints,
            integrity_verified,
        }
    }

    /// Analyze plugin permissions and return a decision + reason.
    fn analyze_permissions(&self, perms: &PluginPermissions) -> (PluginAuditDecision, Option<String>) {
        // Check for excessive memory
        if let Some(max_mem) = perms.max_memory_mb {
            if max_mem > self.max_allowed_memory_mb {
                return (
                    PluginAuditDecision::Reject,
                    Some(format!(
                        "Excessive memory request: {}MB exceeds maximum allowed {}MB",
                        max_mem, self.max_allowed_memory_mb
                    )),
                );
            }
        }

        // Check for excessive CPU time
        if let Some(max_cpu) = perms.max_cpu_time_ms {
            if max_cpu > self.max_allowed_cpu_ms {
                return (
                    PluginAuditDecision::Reject,
                    Some(format!(
                        "Excessive CPU time request: {}ms exceeds maximum allowed {}ms",
                        max_cpu, self.max_allowed_cpu_ms
                    )),
                );
            }
        }

        // Check for dangerous combination: execute + network + filesystem
        if perms.execute && !perms.network.is_empty() && !perms.filesystem.is_empty() {
            return (
                PluginAuditDecision::NeedHumanConfirm,
                Some("Plugin requests execute + network + filesystem access (dangerous combination)".to_string()),
            );
        }

        (PluginAuditDecision::Pass, None)
    }

    /// Generate sandbox constraints based on plugin permissions and security level.
    fn generate_constraints(
        &self,
        perms: &PluginPermissions,
        security_level: PluginSecurityLevel,
    ) -> SandboxConstraints {
        let base = match security_level {
            PluginSecurityLevel::Normal => SandboxConstraints {
                max_memory_mb: perms.max_memory_mb.unwrap_or(128),
                max_cpu_time_ms: perms.max_cpu_time_ms.unwrap_or(10000),
                network_allowed: !perms.network.is_empty(),
                allowed_network: perms.network.clone(),
                filesystem_allowed: !perms.filesystem.is_empty(),
                allowed_filesystem: perms.filesystem.clone(),
                execute_allowed: perms.execute,
                wasm_sandbox: true,
                js_sandbox: true,
            },
            PluginSecurityLevel::Critical => SandboxConstraints {
                max_memory_mb: perms.max_memory_mb.unwrap_or(256),
                max_cpu_time_ms: perms.max_cpu_time_ms.unwrap_or(30000),
                network_allowed: !perms.network.is_empty(),
                allowed_network: perms.network.clone(),
                filesystem_allowed: !perms.filesystem.is_empty(),
                allowed_filesystem: perms.filesystem.clone(),
                execute_allowed: perms.execute,
                wasm_sandbox: true,
                js_sandbox: true,
            },
        };

        // Clamp to maximums
        SandboxConstraints {
            max_memory_mb: base.max_memory_mb.min(self.max_allowed_memory_mb),
            max_cpu_time_ms: base.max_cpu_time_ms.min(self.max_allowed_cpu_ms),
            ..base
        }
    }

    /// Log an audit entry.
    fn log_audit(
        &mut self,
        decision: PluginAuditDecision,
        plugin_name: &str,
        plugin_version: &str,
        integrity_verified: bool,
    ) -> Option<Uuid> {
        let decision_str = match decision {
            PluginAuditDecision::Pass => "Pass",
            PluginAuditDecision::Reject => "Reject",
            PluginAuditDecision::NeedHumanConfirm => "NeedHumanConfirm",
        };
        let entry = self.audit_log.append(
            Decision::Pass, // Plugin audit uses Pass as base (actual decision in source field)
            "Low",
            "PluginAudit",
            "Normal",
            &format!("{}:{} (integrity={})", plugin_name, plugin_version, integrity_verified),
            Some(decision_str),
        );
        Some(entry.entry_id)
    }

    /// Get a reference to the audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }
}

// ============================================================================
// TuckToolGate — tool execution gate implementation
// ============================================================================

/// Tuck tool execution gate — checks tool calls before execution.
///
/// This implements gate #3 (边缘物理闸) for Tentacle tool execution:
/// 1. Parse PFP (4-byte physical fact)
/// 2. Hard real-time decision (sub-μs)
/// 3. Credential injection (if identity_label present and Pass)
/// 4. Sandbox constraint generation
/// 5. Audit logging
pub struct TuckToolGate<S: CredentialStore> {
    /// Security policy.
    policy: SecurityPolicy,
    /// Credential store.
    credential_store: S,
    /// Audit log.
    audit_log: AuditLog,
    /// Source ID.
    source_id: String,
}

impl<S: CredentialStore> TuckToolGate<S> {
    /// Create a new tool gate.
    pub fn new(policy: SecurityPolicy, credential_store: S, source_id: impl Into<String>) -> Self {
        Self {
            policy,
            credential_store,
            audit_log: AuditLog::new(),
            source_id: source_id.into(),
        }
    }

    /// Process a tool execution request.
    pub async fn process(&mut self, request: &ToolExecutionRequest) -> ToolExecutionResponse {
        let trace_id = request.trace_id;

        // Step 1: Parse PFP
        let pfp = match PfpHeader::from_bytes(request.pfp) {
            Ok(pfp) => pfp,
            Err(e) => {
                // Invalid PFP → fail-closed
                return ToolExecutionResponse {
                    trace_id,
                    decision: ToolExecutionDecision::Reject,
                    credential_injected: false,
                    credential: None,
                    audit_entry_id: None,
                    reason: Some(format!("Invalid PFP: {e}")),
                    effective_risk_level: "Unknown".to_string(),
                    sandbox_constraints: SandboxConstraints::strict(),
                };
            }
        };

        let effective_risk = format!("{:?}", pfp.effective_risk_level());

        // Step 2: Hard real-time decision
        let decision = crate::decide(&pfp, &self.policy);

        // Step 3: If Pass and identity_label present, resolve credential
        let (credential_injected, credential) = if matches!(decision, Decision::Pass | Decision::HardOverridePass) {
            if let Some(label_str) = &request.identity_label {
                if let Ok(label) = IdentityLabel::parse(label_str) {
                    if let Ok(cred) = self.credential_store.get(&label).await {
                        (false, Some(cred.expose_secret().to_vec()))
                    } else {
                        (false, None)
                    }
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            }
        } else {
            (false, None)
        };

        // Step 4: Generate sandbox constraints
        let sandbox_constraints = if request.plugin_security_level == PluginSecurityLevel::Critical {
            SandboxConstraints {
                max_memory_mb: 256,
                max_cpu_time_ms: 30000,
                network_allowed: request.involves_network,
                filesystem_allowed: !request.involves_filesystem_write,
                execute_allowed: false,
                wasm_sandbox: true,
                js_sandbox: true,
                ..Default::default()
            }
        } else {
            SandboxConstraints {
                max_memory_mb: 128,
                max_cpu_time_ms: 10000,
                network_allowed: request.involves_network,
                filesystem_allowed: true,
                execute_allowed: false,
                wasm_sandbox: true,
                js_sandbox: true,
                ..Default::default()
            }
        };

        // Step 5: Log audit
        let audit_id = self.log_audit(decision, &request.tool_name, &effective_risk);

        // Step 6: Build reason
        let reason = match decision {
            Decision::Reject => Some("Security policy rejected this tool execution".to_string()),
            Decision::NeedHumanConfirm => Some("Human confirmation required (HITL gate)".to_string()),
            _ => None,
        };

        ToolExecutionResponse {
            trace_id,
            decision: ToolExecutionDecision::from(decision),
            credential_injected,
            credential,
            audit_entry_id: audit_id,
            reason,
            effective_risk_level: effective_risk,
            sandbox_constraints,
        }
    }

    /// Log an audit entry.
    fn log_audit(&mut self, decision: Decision, tool_name: &str, risk_level: &str) -> Option<Uuid> {
        let entry = self.audit_log.append(
            decision,
            risk_level,
            "Executive",
            "Normal",
            tool_name,
            None,
        );
        Some(entry.entry_id)
    }

    /// Get a reference to the audit log.
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }
}

// ============================================================================
// TentacleBridge Trait — pluggable interaction with Tentacle
// ============================================================================

/// Trait for interacting with Helix-Tentacle.
#[async_trait::async_trait]
pub trait TentacleBridge: Send + Sync {
    /// Send a plugin audit response to Tentacle.
    async fn send_plugin_audit_response(&self, response: &PluginAuditResponse) -> Result<(), BridgeError>;

    /// Send a tool execution response to Tentacle.
    async fn send_tool_execution_response(&self, response: &ToolExecutionResponse) -> Result<(), BridgeError>;

    /// Check if the bridge is connected to Tentacle.
    async fn is_connected(&self) -> bool;
}

/// Bridge error (reused from anaphase_bridge).
pub use crate::anaphase_bridge::BridgeError;

// ============================================================================
// NoopTentacleBridge — for testing or standalone deployments
// ============================================================================

/// No-op implementation of TentacleBridge.
#[derive(Debug, Clone, Default)]
pub struct NoopTentacleBridge;

#[async_trait::async_trait]
impl TentacleBridge for NoopTentacleBridge {
    async fn send_plugin_audit_response(&self, _response: &PluginAuditResponse) -> Result<(), BridgeError> {
        Ok(())
    }

    async fn send_tool_execution_response(&self, _response: &ToolExecutionResponse) -> Result<(), BridgeError> {
        Ok(())
    }

    async fn is_connected(&self) -> bool {
        false
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

    fn make_plugin_audit_request(
        security_level: PluginSecurityLevel,
        integrity_match: bool,
        permissions: PluginPermissions,
    ) -> PluginAuditRequest {
        let hash = "abc123".to_string();
        PluginAuditRequest {
            trace_id: Uuid::new_v4(),
            source_id: "tentacle_test".to_string(),
            plugin_name: "test-plugin".to_string(),
            plugin_version: "1.0.0".to_string(),
            security_level,
            integrity_hash: hash.clone(),
            computed_hash: if integrity_match { hash } else { "different".to_string() },
            permissions,
            requires_identity: None,
            source: PluginSource::Local { path: "/tmp/test".to_string() },
        }
    }

    #[test]
    fn test_plugin_audit_pass_normal() {
        let mut auditor = TuckPluginAuditor::new("tuck_test");
        let request = make_plugin_audit_request(
            PluginSecurityLevel::Normal,
            true,
            PluginPermissions::default(),
        );
        let response = auditor.audit_plugin(&request);

        assert_eq!(response.decision, PluginAuditDecision::Pass);
        assert!(response.integrity_verified);
        assert!(response.audit_entry_id.is_some());
        assert!(response.reason.is_none());
    }

    #[test]
    fn test_plugin_audit_integrity_failure() {
        let mut auditor = TuckPluginAuditor::new("tuck_test");
        let request = make_plugin_audit_request(
            PluginSecurityLevel::Normal,
            false, // integrity mismatch
            PluginPermissions::default(),
        );
        let response = auditor.audit_plugin(&request);

        assert_eq!(response.decision, PluginAuditDecision::Reject);
        assert!(!response.integrity_verified);
        assert!(response.reason.is_some());
        assert!(response.reason.unwrap().contains("Integrity"));
    }

    #[test]
    fn test_plugin_audit_critical_needs_hitl() {
        let mut auditor = TuckPluginAuditor::new("tuck_test");
        let request = make_plugin_audit_request(
            PluginSecurityLevel::Critical,
            true,
            PluginPermissions::default(),
        );
        let response = auditor.audit_plugin(&request);

        assert_eq!(response.decision, PluginAuditDecision::NeedHumanConfirm);
        assert!(response.reason.is_some());
    }

    #[test]
    fn test_plugin_audit_excessive_memory() {
        let mut auditor = TuckPluginAuditor::new("tuck_test");
        let perms = PluginPermissions {
            max_memory_mb: Some(2048), // exceeds 1024 max
            ..Default::default()
        };
        let request = make_plugin_audit_request(PluginSecurityLevel::Normal, true, perms);
        let response = auditor.audit_plugin(&request);

        assert_eq!(response.decision, PluginAuditDecision::Reject);
        assert!(response.reason.unwrap().contains("memory"));
    }

    #[test]
    fn test_plugin_audit_dangerous_combination() {
        let mut auditor = TuckPluginAuditor::new("tuck_test");
        let perms = PluginPermissions {
            execute: true,
            network: vec!["*".to_string()],
            filesystem: vec!["/".to_string()],
            ..Default::default()
        };
        let request = make_plugin_audit_request(PluginSecurityLevel::Normal, true, perms);
        let response = auditor.audit_plugin(&request);

        assert_eq!(response.decision, PluginAuditDecision::NeedHumanConfirm);
        assert!(response.reason.unwrap().contains("dangerous combination"));
    }

    #[test]
    fn test_sandbox_constraints_strict() {
        let c = SandboxConstraints::strict();
        assert!(!c.network_allowed);
        assert!(!c.filesystem_allowed);
        assert!(!c.execute_allowed);
        assert!(c.wasm_sandbox);
        assert_eq!(c.max_memory_mb, 64);
    }

    #[test]
    fn test_sandbox_constraints_relaxed() {
        let c = SandboxConstraints::relaxed();
        assert!(c.network_allowed);
        assert!(c.filesystem_allowed);
        assert!(c.execute_allowed);
        assert!(!c.wasm_sandbox);
    }

    #[tokio::test]
    async fn test_tool_gate_pass() {
        let store = InMemoryCredentialStore::new();
        let policy = SecurityPolicy::default();
        let mut gate = TuckToolGate::new(policy, store, "tuck_test");

        let pfp = make_pfp_bytes(RiskLevel::Low, OverrideFlag::Normal);
        let request = ToolExecutionRequest {
            trace_id: Uuid::new_v4(),
            source_id: "tentacle_test".to_string(),
            tool_name: "test-plugin.tool_fn".to_string(),
            args: serde_json::json!({}),
            pfp,
            identity_label: None,
            plugin_security_level: PluginSecurityLevel::Normal,
            involves_network: false,
            involves_filesystem_write: false,
            involves_credential: false,
        };
        let response = gate.process(&request).await;

        assert_eq!(response.decision, ToolExecutionDecision::Pass);
        assert!(response.audit_entry_id.is_some());
        assert_eq!(response.effective_risk_level, "Low");
    }

    #[tokio::test]
    async fn test_tool_gate_reject_catastrophic() {
        let store = InMemoryCredentialStore::new();
        let policy = SecurityPolicy::default();
        let mut gate = TuckToolGate::new(policy, store, "tuck_test");

        let pfp = make_pfp_bytes(RiskLevel::Catastrophic, OverrideFlag::Normal);
        let request = ToolExecutionRequest {
            trace_id: Uuid::new_v4(),
            source_id: "tentacle_test".to_string(),
            tool_name: "test.dangerous".to_string(),
            args: serde_json::json!({}),
            pfp,
            identity_label: None,
            plugin_security_level: PluginSecurityLevel::Critical,
            involves_network: true,
            involves_filesystem_write: true,
            involves_credential: false,
        };
        let response = gate.process(&request).await;

        assert_eq!(response.decision, ToolExecutionDecision::Reject);
        assert!(response.reason.is_some());
    }

    #[tokio::test]
    async fn test_tool_gate_with_credential() {
        let store = InMemoryCredentialStore::new();
        store.insert("env:test/key", b"tool-secret");
        let policy = SecurityPolicy::default();
        let mut gate = TuckToolGate::new(policy, store, "tuck_test");

        let pfp = make_pfp_bytes(RiskLevel::Low, OverrideFlag::Normal);
        let request = ToolExecutionRequest {
            trace_id: Uuid::new_v4(),
            source_id: "tentacle_test".to_string(),
            tool_name: "test.api_call".to_string(),
            args: serde_json::json!({}),
            pfp,
            identity_label: Some("env:test/key".to_string()),
            plugin_security_level: PluginSecurityLevel::Normal,
            involves_network: true,
            involves_filesystem_write: false,
            involves_credential: true,
        };
        let response = gate.process(&request).await;

        assert_eq!(response.decision, ToolExecutionDecision::Pass);
        assert!(response.credential.is_some());
        assert_eq!(response.credential.unwrap(), b"tool-secret");
    }

    #[test]
    fn test_plugin_audit_request_serialization() {
        let request = make_plugin_audit_request(PluginSecurityLevel::Normal, true, PluginPermissions::default());
        let json = serde_json::to_string(&request).unwrap();
        let parsed: PluginAuditRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.plugin_name, "test-plugin");
        assert_eq!(parsed.security_level, PluginSecurityLevel::Normal);
    }

    #[tokio::test]
    async fn test_noop_tentacle_bridge() {
        let bridge = NoopTentacleBridge;
        assert!(!bridge.is_connected().await);

        let response = PluginAuditResponse {
            trace_id: Uuid::new_v4(),
            decision: PluginAuditDecision::Pass,
            audit_entry_id: None,
            reason: None,
            sandbox_constraints: SandboxConstraints::default(),
            integrity_verified: true,
        };
        assert!(bridge.send_plugin_audit_response(&response).await.is_ok());
    }
}
