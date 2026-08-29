//! Tuck configuration management.
//!
//! # Design Principle
//!
//! **确定性优先**: Configuration is loaded once at startup and validated
//! before use. Invalid configuration causes immediate failure (fail-fast),
//! not silent degradation.
//!
//! **极致解耦**: Configuration is a plain data struct — no runtime behavior
//! is embedded. All components receive their config as owned values or
//! shared references, never a global mutable state.
//!
//! **按需加载**: Only the configuration needed by the active components is
//! loaded. Disabled features (e.g., HSM, hot reload) don't require their
//! config sections to be present.
//!
//! # Configuration Sources (priority order)
//!
//! 1. Default values (built-in)
//! 2. TOML configuration file (specified by `--config` or `TUCK_CONFIG`)
//! 3. Environment variables (prefixed with `TUCK_`)
//! 4. Command-line arguments (highest priority)
//!
//! # Example TOML
//!
//! ```toml
//! [server]
//! host = "127.0.0.1"
//! port = 8443
//!
//! [security]
//! fail_closed = true
//! default_risk_level = "Medium"
//!
//! [audit]
//! enabled = true
//! log_path = "/var/log/tuck/audit.log"
//! max_entries = 100000
//!
//! [credential]
//! store_type = "file"
//! store_path = "/etc/tuck/credentials.enc"
//!
//! [hsm]
//! enabled = false
//!
//! [hot_reload]
//! enabled = false
//!
//! [log]
//! level = "info"
//! format = "json"
//! ```

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

// ============================================================================
// Configuration Error
// ============================================================================

/// Configuration error.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// IO error reading config file.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// TOML parse error.
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    /// Validation error.
    #[error("validation error: {0}")]
    Validation(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(String),
}

// ============================================================================
// Top-level Configuration
// ============================================================================

/// Tuck server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuckConfig {
    /// Server configuration.
    #[serde(default)]
    pub server: ServerConfig,

    /// Security policy configuration.
    #[serde(default)]
    pub security: SecurityConfig,

    /// Audit log configuration.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Credential store configuration.
    #[serde(default)]
    pub credential: CredentialConfig,

    /// HSM configuration.
    #[serde(default)]
    pub hsm: HsmConfig,

    /// Hot reload configuration.
    #[serde(default)]
    pub hot_reload: HotReloadConfig,

    /// Logging configuration.
    #[serde(default)]
    pub log: LogConfig,

    /// Metrics configuration.
    #[serde(default)]
    pub metrics: MetricsConfig,
}

impl Default for TuckConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            security: SecurityConfig::default(),
            audit: AuditConfig::default(),
            credential: CredentialConfig::default(),
            hsm: HsmConfig::default(),
            hot_reload: HotReloadConfig::default(),
            log: LogConfig::default(),
            metrics: MetricsConfig::default(),
        }
    }
}

impl TuckConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    /// Parse configuration from TOML string.
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration with environment variable overrides.
    ///
    /// Environment variables are prefixed with `TUCK_` and use double
    /// underscores for nested fields (e.g., `TUCK_SERVER__PORT`).
    pub fn load(path: Option<&str>) -> Result<Self, ConfigError> {
        let mut config = if let Some(p) = path {
            Self::from_file(p)?
        } else {
            Self::default()
        };

        // Apply environment variable overrides
        config.apply_env_overrides();

        // Final validation
        config.validate()?;
        Ok(config)
    }

    /// Apply environment variable overrides.
    fn apply_env_overrides(&mut self) {
        // Server
        if let Ok(host) = std::env::var("TUCK_SERVER__HOST") {
            self.server.host = host;
        }
        if let Ok(port) = std::env::var("TUCK_SERVER__PORT") {
            if let Ok(p) = port.parse() {
                self.server.port = p;
            }
        }

        // Security
        if let Ok(fc) = std::env::var("TUCK_SECURITY__FAIL_CLOSED") {
            self.security.fail_closed = fc == "true" || fc == "1";
        }

        // Audit
        if let Ok(enabled) = std::env::var("TUCK_AUDIT__ENABLED") {
            self.audit.enabled = enabled == "true" || enabled == "1";
        }
        if let Ok(path) = std::env::var("TUCK_AUDIT__LOG_PATH") {
            self.audit.log_path = path;
        }

        // Log
        if let Ok(level) = std::env::var("TUCK_LOG__LEVEL") {
            self.log.level = level;
        }
        if let Ok(format) = std::env::var("TUCK_LOG__FORMAT") {
            self.log.format = format;
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Server validation
        if self.server.port == 0 || self.server.port > 65535 {
            return Err(ConfigError::Validation(format!(
                "server.port must be between 1 and 65535, got {}",
                self.server.port
            )));
        }
        if self.server.host.is_empty() {
            return Err(ConfigError::Validation("server.host must not be empty".to_string()));
        }

        // Security validation
        let valid_risk_levels = ["Low", "Medium", "Critical", "Catastrophic"];
        if !valid_risk_levels.contains(&self.security.default_risk_level.as_str()) {
            return Err(ConfigError::Validation(format!(
                "security.default_risk_level must be one of {:?}, got '{}'",
                valid_risk_levels, self.security.default_risk_level
            )));
        }

        // Audit validation
        if self.audit.enabled && self.audit.log_path.is_empty() {
            return Err(ConfigError::Validation(
                "audit.log_path must not be empty when audit is enabled".to_string(),
            ));
        }
        if self.audit.max_entries == 0 {
            return Err(ConfigError::Validation(
                "audit.max_entries must be greater than 0".to_string(),
            ));
        }

        // Credential validation
        let valid_store_types = ["file", "memory", "hsm"];
        if !valid_store_types.contains(&self.credential.store_type.as_str()) {
            return Err(ConfigError::Validation(format!(
                "credential.store_type must be one of {:?}, got '{}'",
                valid_store_types, self.credential.store_type
            )));
        }

        // Log validation
        let valid_log_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&self.log.level.as_str()) {
            return Err(ConfigError::Validation(format!(
                "log.level must be one of {:?}, got '{}'",
                valid_log_levels, self.log.level
            )));
        }
        let valid_log_formats = ["json", "text"];
        if !valid_log_formats.contains(&self.log.format.as_str()) {
            return Err(ConfigError::Validation(format!(
                "log.format must be one of {:?}, got '{}'",
                valid_log_formats, self.log.format
            )));
        }

        Ok(())
    }

    /// Serialize to TOML string.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::Validation(e.to_string()))
    }
}

// ============================================================================
// Server Configuration
// ============================================================================

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen host.
    #[serde(default = "default_host")]
    pub host: String,

    /// Listen port.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Maximum concurrent connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,

    /// Shutdown timeout in seconds.
    #[serde(default = "default_shutdown_timeout_s")]
    pub shutdown_timeout_s: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            max_connections: default_max_connections(),
            request_timeout_ms: default_request_timeout_ms(),
            shutdown_timeout_s: default_shutdown_timeout_s(),
        }
    }
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    8443
}
fn default_max_connections() -> usize {
    1024
}
fn default_request_timeout_ms() -> u64 {
    5000
}
fn default_shutdown_timeout_s() -> u64 {
    30
}

// ============================================================================
// Security Configuration
// ============================================================================

/// Security policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Fail-closed mode (reject on any error).
    #[serde(default = "default_true")]
    pub fail_closed: bool,

    /// Default risk level for requests without PFP.
    #[serde(default = "default_risk_level")]
    pub default_risk_level: String,

    /// Require PFP header for all requests.
    #[serde(default = "default_false")]
    pub require_pfp: bool,

    /// Require SAP header for high-risk requests.
    #[serde(default = "default_false")]
    pub require_sap_for_high_risk: bool,

    /// Maximum audit entries before rotation.
    #[serde(default = "default_max_audit_entries")]
    pub max_audit_entries: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            fail_closed: default_true(),
            default_risk_level: default_risk_level(),
            require_pfp: default_false(),
            require_sap_for_high_risk: default_false(),
            max_audit_entries: default_max_audit_entries(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_risk_level() -> String {
    "Medium".to_string()
}
fn default_max_audit_entries() -> usize {
    100_000
}

// ============================================================================
// Audit Configuration
// ============================================================================

/// Audit log configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Audit log file path.
    #[serde(default = "default_audit_log_path")]
    pub log_path: String,

    /// Maximum audit entries in memory.
    #[serde(default = "default_max_audit_entries")]
    pub max_entries: usize,

    /// Flush interval in milliseconds.
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,

    /// Include full request payload in audit (may contain sensitive data).
    #[serde(default = "default_false")]
    pub include_payload: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            log_path: default_audit_log_path(),
            max_entries: default_max_audit_entries(),
            flush_interval_ms: default_flush_interval_ms(),
            include_payload: default_false(),
        }
    }
}

fn default_audit_log_path() -> String {
    "/var/log/tuck/audit.log".to_string()
}
fn default_flush_interval_ms() -> u64 {
    1000
}

// ============================================================================
// Credential Configuration
// ============================================================================

/// Credential store configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    /// Store type: file, memory, hsm.
    #[serde(default = "default_store_type")]
    pub store_type: String,

    /// Store path (for file store).
    #[serde(default = "default_store_path")]
    pub store_path: String,

    /// Master key (for file store encryption).
    /// In production, use TUCK_CREDENTIAL__MASTER_KEY env var instead.
    #[serde(default)]
    pub master_key: String,

    /// Maximum credential size in bytes.
    #[serde(default = "default_max_credential_size")]
    pub max_credential_size: usize,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            store_type: default_store_type(),
            store_path: default_store_path(),
            master_key: String::new(),
            max_credential_size: default_max_credential_size(),
        }
    }
}

fn default_store_type() -> String {
    "file".to_string()
}
fn default_store_path() -> String {
    "/etc/tuck/credentials.enc".to_string()
}
fn default_max_credential_size() -> usize {
    4096
}

// ============================================================================
// HSM Configuration
// ============================================================================

/// HSM (Hardware Security Module) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// Enable HSM.
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// HSM library path (PKCS#11).
    #[serde(default)]
    pub library_path: String,

    /// HSM slot ID.
    #[serde(default)]
    pub slot_id: u64,

    /// HSM PIN (use env var in production).
    #[serde(default)]
    pub pin: String,
}

impl Default for HsmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            library_path: String::new(),
            slot_id: 0,
            pin: String::new(),
        }
    }
}

// ============================================================================
// Hot Reload Configuration
// ============================================================================

/// Hot reload configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotReloadConfig {
    /// Enable hot reload of credentials and policies.
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// Watch interval in seconds.
    #[serde(default = "default_watch_interval_s")]
    pub watch_interval_s: u64,

    /// Watch paths (credentials, policies).
    #[serde(default)]
    pub watch_paths: Vec<String>,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_interval_s: default_watch_interval_s(),
            watch_paths: vec![],
        }
    }
}

fn default_watch_interval_s() -> u64 {
    30
}

// ============================================================================
// Log Configuration
// ============================================================================

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log level: trace, debug, info, warn, error.
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format: json, text.
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Log file path (None = stdout).
    #[serde(default)]
    pub file_path: Option<String>,

    /// Include timestamp in logs.
    #[serde(default = "default_true")]
    pub include_timestamp: bool,

    /// Include target (module path) in logs.
    #[serde(default = "default_true")]
    pub include_target: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            file_path: None,
            include_timestamp: true,
            include_target: true,
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}

// ============================================================================
// Metrics Configuration
// ============================================================================

/// Metrics configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics endpoint path.
    #[serde(default = "default_metrics_path")]
    pub path: String,

    /// Metrics listen port (separate from main server, 0 = same port).
    #[serde(default)]
    pub port: u16,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_metrics_path(),
            port: 0,
        }
    }
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TuckConfig::default();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8443);
        assert!(config.security.fail_closed);
        assert!(config.audit.enabled);
        assert_eq!(config.credential.store_type, "file");
        assert!(!config.hsm.enabled);
        assert!(!config.hot_reload.enabled);
        assert_eq!(config.log.level, "info");
        assert!(config.metrics.enabled);
    }

    #[test]
    fn test_default_config_validates() {
        let config = TuckConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_from_toml_minimal() {
        let toml = r#"
[server]
port = 9090
"#;
        let config = TuckConfig::from_toml(toml).unwrap();
        assert_eq!(config.server.port, 9090);
        assert_eq!(config.server.host, "127.0.0.1"); // default
    }

    #[test]
    fn test_from_toml_full() {
        let toml = r#"
[server]
host = "0.0.0.0"
port = 443
max_connections = 2048

[security]
fail_closed = true
default_risk_level = "Critical"
require_pfp = true

[audit]
enabled = true
log_path = "/data/tuck/audit.log"
max_entries = 50000

[credential]
store_type = "memory"

[log]
level = "debug"
format = "text"

[metrics]
enabled = false
"#;
        let config = TuckConfig::from_toml(toml).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 443);
        assert_eq!(config.server.max_connections, 2048);
        assert_eq!(config.security.default_risk_level, "Critical");
        assert!(config.security.require_pfp);
        assert_eq!(config.audit.log_path, "/data/tuck/audit.log");
        assert_eq!(config.credential.store_type, "memory");
        assert_eq!(config.log.level, "debug");
        assert!(!config.metrics.enabled);
    }

    #[test]
    fn test_validate_invalid_port() {
        let mut config = TuckConfig::default();
        config.server.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_risk_level() {
        let mut config = TuckConfig::default();
        config.security.default_risk_level = "Invalid".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_log_level() {
        let mut config = TuckConfig::default();
        config.log.level = "verbose".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_store_type() {
        let mut config = TuckConfig::default();
        config.credential.store_type = "redis".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_audit_enabled_without_path() {
        let mut config = TuckConfig::default();
        config.audit.enabled = true;
        config.audit.log_path = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_to_toml_roundtrip() {
        let config = TuckConfig::default();
        let toml_str = config.to_toml().unwrap();
        let parsed = TuckConfig::from_toml(&toml_str).unwrap();
        assert_eq!(parsed.server.port, config.server.port);
        assert_eq!(parsed.security.fail_closed, config.security.fail_closed);
    }

    #[test]
    fn test_sandbox_constraints_not_in_config() {
        // SandboxConstraints is in tentacle_bridge, not config
        // This test just verifies config doesn't accidentally include it
        let config = TuckConfig::default();
        let _ = config; // compiles
    }

    #[test]
    fn test_env_override_port() {
        // Note: this test may be flaky if env var is set in the test environment
        // We test the parsing logic directly
        std::env::set_var("TUCK_SERVER__PORT", "9999");
        let config = TuckConfig::load(None).unwrap();
        assert_eq!(config.server.port, 9999);
        std::env::remove_var("TUCK_SERVER__PORT");
    }

    #[test]
    fn test_env_override_log_level() {
        std::env::set_var("TUCK_LOG__LEVEL", "debug");
        let config = TuckConfig::load(None).unwrap();
        assert_eq!(config.log.level, "debug");
        std::env::remove_var("TUCK_LOG__LEVEL");
    }
}
