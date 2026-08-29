//! Policy configuration — serializable, versioned, file-based security policy.
//!
//! This module provides the *configuration layer* for Tuck's security policy.
//! The hard real-time `SecurityPolicy` in `crate::SecurityPolicy` is the
//! in-memory decision engine; `PolicyConfig` is the serializable, file-based
//! representation that can be loaded, saved, and hot-reloaded.
//!
//! # Design Principle
//!
//! **极致解耦**: Policy configuration (file I/O, serialization, versioning)
//! is separate from the hard real-time decision engine. The `decide()` function
//! only reads `SecurityPolicy` fields — no file I/O, no serialization, no locks.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{Decision, SecurityPolicy};

// ============================================================================
// Policy version
// ============================================================================

/// Policy version — semantic versioning for security policy files.
///
/// Used to track policy changes and ensure compatibility. The audit log
/// records the policy version used for each decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyVersion {
    /// Major version — incompatible policy format changes.
    pub major: u32,
    /// Minor version — backward-compatible policy additions.
    pub minor: u32,
    /// Patch version — bug fixes and tuning.
    pub patch: u32,
}

impl PolicyVersion {
    /// Current policy format version.
    pub const CURRENT: PolicyVersion = PolicyVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };

    /// Create a new policy version.
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Check if this version is compatible with another (same major version).
    pub fn is_compatible_with(&self, other: &PolicyVersion) -> bool {
        self.major == other.major
    }
}

impl std::fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Default for PolicyVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

// ============================================================================
// Serializable decision (string-based for config files)
// ============================================================================

/// Serializable decision — string-based representation for config files.
///
/// Using string names instead of enum integers makes config files human-readable
/// and forward-compatible. Conversion to/from `Decision` is explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionConfig {
    /// Pass — frame continues to flow.
    Pass,
    /// Reject — frame is dropped.
    Reject,
    /// Need human confirm — frame is paused, human confirmation required.
    NeedHumanConfirm,
    /// Hard override pass — unconditional pass (CATASTROPHIC + Override-Flag).
    HardOverridePass,
}

impl From<DecisionConfig> for Decision {
    fn from(value: DecisionConfig) -> Self {
        match value {
            DecisionConfig::Pass => Decision::Pass,
            DecisionConfig::Reject => Decision::Reject,
            DecisionConfig::NeedHumanConfirm => Decision::NeedHumanConfirm,
            DecisionConfig::HardOverridePass => Decision::HardOverridePass,
        }
    }
}

impl From<Decision> for DecisionConfig {
    fn from(value: Decision) -> Self {
        match value {
            Decision::Pass => DecisionConfig::Pass,
            Decision::Reject => DecisionConfig::Reject,
            Decision::NeedHumanConfirm => DecisionConfig::NeedHumanConfirm,
            Decision::HardOverridePass => DecisionConfig::HardOverridePass,
        }
    }
}

// ============================================================================
// Policy config — serializable, file-based security policy
// ============================================================================

/// Policy configuration — serializable, versioned, file-based security policy.
///
/// This is the *configuration layer* representation. Convert to `SecurityPolicy`
/// for use in the hard real-time `decide()` path via `to_policy()`.
///
/// # File Format (TOML)
///
/// ```toml
/// [policy]
/// version = "1.0.0"
/// description = "Default Tuck security policy"
///
/// [policy.risk_levels]
/// low = "pass"
/// medium = "pass"
/// critical = "need_human_confirm"
/// catastrophic = "reject"
/// catastrophic_override = "hard_override_pass"
///
/// [policy.options]
/// external_additional_check = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Policy metadata.
    pub policy: PolicyMeta,
    /// Risk level to decision mappings.
    pub risk_levels: RiskLevelConfig,
    /// Additional policy options.
    #[serde(default)]
    pub options: PolicyOptions,
}

/// Policy metadata — version, description, timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMeta {
    /// Policy version (semantic).
    pub version: PolicyVersion,
    /// Human-readable description of this policy.
    #[serde(default)]
    pub description: String,
    /// Creation timestamp (RFC3339).
    #[serde(default)]
    pub created_at: String,
    /// Last update timestamp (RFC3339).
    #[serde(default)]
    pub updated_at: String,
}

/// Risk level configuration — maps each risk level to a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskLevelConfig {
    /// Decision for LOW risk.
    pub low: DecisionConfig,
    /// Decision for MEDIUM risk.
    pub medium: DecisionConfig,
    /// Decision for CRITICAL risk.
    pub critical: DecisionConfig,
    /// Decision for CATASTROPHIC risk (without Override-Flag).
    pub catastrophic: DecisionConfig,
    /// Decision for CATASTROPHIC + HardOverride.
    pub catastrophic_override: DecisionConfig,
}

/// Additional policy options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOptions {
    /// Whether external output (Output-Dest=EXTERNAL) requires additional check.
    #[serde(default = "default_external_check")]
    pub external_additional_check: bool,
    /// Human confirmation timeout in seconds (for NeedHumanConfirm).
    #[serde(default = "default_confirm_timeout")]
    pub human_confirm_timeout_secs: u64,
    /// Whether to enable SAP replay protection (optional enhancement).
    #[serde(default)]
    pub enable_sap_replay_protection: bool,
}

fn default_external_check() -> bool {
    true
}

fn default_confirm_timeout() -> u64 {
    30
}

impl Default for PolicyOptions {
    fn default() -> Self {
        Self {
            external_additional_check: default_external_check(),
            human_confirm_timeout_secs: default_confirm_timeout(),
            enable_sap_replay_protection: false,
        }
    }
}

// ============================================================================
// Conversions
// ============================================================================

impl PolicyConfig {
    /// Convert to `SecurityPolicy` for use in the hard real-time `decide()` path.
    ///
    /// This conversion extracts only the fields needed by `decide()` and
    /// discards metadata (version, timestamps, descriptions).
    pub fn to_policy(&self) -> SecurityPolicy {
        SecurityPolicy {
            low: self.risk_levels.low.into(),
            medium: self.risk_levels.medium.into(),
            critical: self.risk_levels.critical.into(),
            catastrophic: self.risk_levels.catastrophic.into(),
            catastrophic_override: self.risk_levels.catastrophic_override.into(),
            external_additional_check: self.options.external_additional_check,
        }
    }

    /// Get the policy version.
    pub fn version(&self) -> PolicyVersion {
        self.policy.version
    }

    /// Load policy from a TOML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, PolicyConfigError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| PolicyConfigError::Io(e.to_string()))?;
        Self::from_toml(&content)
    }

    /// Parse policy from TOML string.
    pub fn from_toml(content: &str) -> Result<Self, PolicyConfigError> {
        let config: Self = toml::from_str(content)
            .map_err(|e| PolicyConfigError::Parse(e.to_string()))?;
        // Validate version compatibility
        if !config.policy.version.is_compatible_with(&PolicyVersion::CURRENT) {
            return Err(PolicyConfigError::IncompatibleVersion {
                found: config.policy.version,
                expected: PolicyVersion::CURRENT,
            });
        }
        Ok(config)
    }

    /// Save policy to a TOML file.
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), PolicyConfigError> {
        let content = self.to_toml()?;
        std::fs::write(path.as_ref(), content)
            .map_err(|e| PolicyConfigError::Io(e.to_string()))?;
        Ok(())
    }

    /// Serialize policy to TOML string.
    pub fn to_toml(&self) -> Result<String, PolicyConfigError> {
        toml::to_string_pretty(self)
            .map_err(|e| PolicyConfigError::Serialize(e.to_string()))
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        let now = chrono_now();
        Self {
            policy: PolicyMeta {
                version: PolicyVersion::CURRENT,
                description: "Default Tuck security policy".to_string(),
                created_at: now.clone(),
                updated_at: now,
            },
            risk_levels: RiskLevelConfig {
                low: DecisionConfig::Pass,
                medium: DecisionConfig::Pass,
                critical: DecisionConfig::NeedHumanConfirm,
                catastrophic: DecisionConfig::Reject,
                catastrophic_override: DecisionConfig::HardOverridePass,
            },
            options: PolicyOptions::default(),
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Policy configuration error.
#[derive(Debug, thiserror::Error)]
pub enum PolicyConfigError {
    /// I/O error (file read/write).
    #[error("I/O error: {0}")]
    Io(String),
    /// Parse error (invalid TOML).
    #[error("parse error: {0}")]
    Parse(String),
    /// Serialize error.
    #[error("serialize error: {0}")]
    Serialize(String),
    /// Incompatible policy version.
    #[error("incompatible policy version: found {found}, expected major {expected}")]
    IncompatibleVersion {
        /// Found version.
        found: PolicyVersion,
        /// Expected version.
        expected: PolicyVersion,
    },
}

// ============================================================================
// Helper: current timestamp (no external chrono dependency, use std)
// ============================================================================

fn chrono_now() -> String {
    // Use std::time to create a simple ISO-like timestamp.
    // For production, use the `chrono` crate. This is a minimal fallback.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix-{}", secs)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_config() {
        let config = PolicyConfig::default();
        assert_eq!(config.version(), PolicyVersion::CURRENT);
        assert_eq!(config.risk_levels.low, DecisionConfig::Pass);
        assert_eq!(config.risk_levels.critical, DecisionConfig::NeedHumanConfirm);
        assert_eq!(config.risk_levels.catastrophic, DecisionConfig::Reject);
        assert_eq!(
            config.risk_levels.catastrophic_override,
            DecisionConfig::HardOverridePass
        );
    }

    #[test]
    fn test_to_policy_conversion() {
        let config = PolicyConfig::default();
        let policy = config.to_policy();
        assert_eq!(policy.low, Decision::Pass);
        assert_eq!(policy.medium, Decision::Pass);
        assert_eq!(policy.critical, Decision::NeedHumanConfirm);
        assert_eq!(policy.catastrophic, Decision::Reject);
        assert_eq!(policy.catastrophic_override, Decision::HardOverridePass);
        assert!(policy.external_additional_check);
    }

    #[test]
    fn test_toml_roundtrip() {
        let config = PolicyConfig::default();
        let toml_str = config.to_toml().unwrap();
        let parsed = PolicyConfig::from_toml(&toml_str).unwrap();
        assert_eq!(parsed.version(), config.version());
        assert_eq!(parsed.risk_levels.low, config.risk_levels.low);
        assert_eq!(parsed.risk_levels.critical, config.risk_levels.critical);
        assert_eq!(
            parsed.risk_levels.catastrophic_override,
            config.risk_levels.catastrophic_override
        );
    }

    #[test]
    fn test_toml_contains_expected_fields() {
        let config = PolicyConfig::default();
        let toml_str = config.to_toml().unwrap();
        assert!(toml_str.contains("[policy]"));
        assert!(toml_str.contains("version"));
        assert!(toml_str.contains("[risk_levels]"));
        assert!(toml_str.contains("low = \"pass\""));
        assert!(toml_str.contains("critical = \"need_human_confirm\""));
        assert!(toml_str.contains("catastrophic = \"reject\""));
        assert!(toml_str.contains("catastrophic_override = \"hard_override_pass\""));
    }

    #[test]
    fn test_file_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("tuck_test_policy.toml");
        let config = PolicyConfig::default();
        config.to_file(&path).unwrap();
        let loaded = PolicyConfig::from_file(&path).unwrap();
        assert_eq!(loaded.version(), config.version());
        assert_eq!(loaded.risk_levels.low, config.risk_levels.low);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_incompatible_version() {
        let toml_str = r#"
[policy]
version = { major = 2, minor = 0, patch = 0 }
description = "Future version"

[risk_levels]
low = "pass"
medium = "pass"
critical = "reject"
catastrophic = "reject"
catastrophic_override = "hard_override_pass"
"#;
        let result = PolicyConfig::from_toml(toml_str);
        assert!(matches!(
            result,
            Err(PolicyConfigError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn test_decision_config_conversion() {
        for dc in [
            DecisionConfig::Pass,
            DecisionConfig::Reject,
            DecisionConfig::NeedHumanConfirm,
            DecisionConfig::HardOverridePass,
        ] {
            let d: Decision = dc.into();
            let dc2: DecisionConfig = d.into();
            assert_eq!(dc, dc2);
        }
    }

    #[test]
    fn test_policy_version_display() {
        let v = PolicyVersion::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
        assert!(v.is_compatible_with(&PolicyVersion::new(1, 99, 99)));
        assert!(!v.is_compatible_with(&PolicyVersion::new(2, 0, 0)));
    }

    #[test]
    fn test_custom_policy() {
        let toml_str = r#"
[policy]
version = { major = 1, minor = 0, patch = 0 }
description = "Strict policy"

[risk_levels]
low = "pass"
medium = "need_human_confirm"
critical = "reject"
catastrophic = "reject"
catastrophic_override = "hard_override_pass"

[options]
external_additional_check = true
human_confirm_timeout_secs = 60
enable_sap_replay_protection = true
"#;
        let config = PolicyConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.risk_levels.medium, DecisionConfig::NeedHumanConfirm);
        assert_eq!(config.risk_levels.critical, DecisionConfig::Reject);
        assert_eq!(config.options.human_confirm_timeout_secs, 60);
        assert!(config.options.enable_sap_replay_protection);
        let policy = config.to_policy();
        assert_eq!(policy.medium, Decision::NeedHumanConfirm);
        assert_eq!(policy.critical, Decision::Reject);
    }
}
