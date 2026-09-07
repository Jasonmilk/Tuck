//! Tuck structured logging initialization.
//!
//! # Design Principle
//!
//! **确定性优先**: Logging is initialized once at startup based on LogConfig.
//! No runtime changes to log level or format after initialization.
//!
//! **极致解耦**: This module lives in the `tuck` binary crate, not `tuck-core`.
//! The core library only depends on the `tracing` facade (no subscriber
//! implementation). The binary assembles the subscriber at startup.
//!
//! **按需加载**: Logging is only initialized when the binary runs. When
//! tuck-core is used as a library, no logging subscriber is set up — the
//! embedding application controls its own logging.
//!
//! **白盒可观测**: JSON log format includes timestamp, level, target,
//! and structured fields for machine parsing. Text format is human-readable.

use std::fs::File;
use std::sync::Arc;
use thiserror::Error;
use tracing_subscriber::{fmt, EnvFilter};

use tuck_core::config::LogConfig;
// ============================================================================
// Logging Error
// ============================================================================

/// Logging initialization error.
#[derive(Debug, Error)]
pub enum LoggingError {
    /// IO error opening log file.
    #[error("IO error opening log file: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid log level.
    #[error("invalid log level: {0}")]
    InvalidLevel(String),
}

// ============================================================================
// Logging Guard
// ============================================================================

/// Logging guard — keeps the log file handle alive for the lifetime of the
/// application. Dropping the guard flushes and closes the log file.
pub struct LoggingGuard {
    /// Optional file handle (kept alive to prevent early flush).
    _file_handle: Option<Arc<File>>,
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize structured logging based on LogConfig.
///
/// # Flow
///
/// 1. Parse log level from config (fallback to RUST_LOG env var)
/// 2. Choose format (JSON or text)
/// 3. Choose output (stdout or file)
/// 4. Build and install the tracing subscriber
/// 5. Return a guard that keeps the log file alive
///
/// # Example
///
/// ```no_run
/// use tuck_core::config::LogConfig;
/// use tuck::logging::init_logging;
///
/// let config = LogConfig::default();
/// let _guard = init_logging(&config).expect("logging init failed");
/// ```
pub fn init_logging(config: &LogConfig) -> Result<LoggingGuard, LoggingError> {
    // Step 1: Build env filter from log level
    let filter = build_env_filter(&config.level)?;

    // Step 2: Open log file if specified
    let (file_handle, is_file) = if let Some(path) = &config.file_path {
        let file = File::options()
            .create(true)
            .write(true)
            .append(true)
            .open(path)?;
        (Some(Arc::new(file)), true)
    } else {
        (None, false)
    };

    // Step 3: Build subscriber based on format and output
    if is_file {
        let file = file_handle.clone().unwrap();
        match config.format.as_str() {
            "json" => {
                let builder = fmt::Subscriber::builder()
                    .json()
                    .with_env_filter(filter)
                    .with_writer(file)
                    .with_target(config.include_target)
                    .with_ansi(false);
                if config.include_timestamp {
                    let _ = tracing::subscriber::set_global_default(builder.finish());
                } else {
                    let _ = tracing::subscriber::set_global_default(builder.without_time().finish());
                }
            }
            _ => {
                let builder = fmt::Subscriber::builder()
                    .with_env_filter(filter)
                    .with_writer(file)
                    .with_target(config.include_target)
                    .with_ansi(false);
                if config.include_timestamp {
                    let _ = tracing::subscriber::set_global_default(builder.finish());
                } else {
                    let _ = tracing::subscriber::set_global_default(builder.without_time().finish());
                }
            }
        }
    } else {
        match config.format.as_str() {
            "json" => {
                let builder = fmt::Subscriber::builder()
                    .json()
                    .with_env_filter(filter)
                    .with_target(config.include_target)
                    .with_ansi(false);
                if config.include_timestamp {
                    let _ = tracing::subscriber::set_global_default(builder.finish());
                } else {
                    let _ = tracing::subscriber::set_global_default(builder.without_time().finish());
                }
            }
            _ => {
                let builder = fmt::Subscriber::builder()
                    .with_env_filter(filter)
                    .with_target(config.include_target)
                    .with_ansi(true);
                if config.include_timestamp {
                    let _ = tracing::subscriber::set_global_default(builder.finish());
                } else {
                    let _ = tracing::subscriber::set_global_default(builder.without_time().finish());
                }
            }
        }
    }

    // Step 4: Return guard (file handle kept alive)
    Ok(LoggingGuard {
        _file_handle: file_handle,
    })
}

/// Build EnvFilter from log level string.
fn build_env_filter(level: &str) -> Result<EnvFilter, LoggingError> {
    // Validate level
    match level.to_lowercase().as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => {}
        other => return Err(LoggingError::InvalidLevel(other.to_string())),
    }

    // Try RUST_LOG first, fallback to config level
    if std::env::var("RUST_LOG").is_ok() {
        Ok(EnvFilter::from_default_env())
    } else {
        EnvFilter::try_new(format!("{},tuck=info,tuck_core=info", level))
            .map_err(|e| LoggingError::InvalidLevel(e.to_string()))
    }
}

// ============================================================================
// Convenience macros (re-exported for use in tuck-core)
// ============================================================================

/// Log a security event at WARN level with structured fields.
#[macro_export]
macro_rules! security_event {
    ($($arg:tt)*) => {
        tracing::warn!(target: "tuck::security", $($arg)*)
    };
}

/// Log an audit event at INFO level with structured fields.
#[macro_export]
macro_rules! audit_event {
    ($($arg:tt)*) => {
        tracing::info!(target: "tuck::audit", $($arg)*)
    };
}

/// Log a decision at DEBUG level with structured fields.
#[macro_export]
macro_rules! decision_log {
    ($($arg:tt)*) => {
        tracing::debug!(target: "tuck::decision", $($arg)*)
    };
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_env_filter_valid_levels() {
        for level in &["trace", "debug", "info", "warn", "error"] {
            assert!(build_env_filter(level).is_ok(), "level {} should be valid", level);
        }
    }

    #[test]
    fn test_build_env_filter_invalid_level() {
        assert!(build_env_filter("verbose").is_err());
        assert!(build_env_filter("").is_err());
    }

    #[test]
    fn test_init_logging_text_stdout() {
        let config = LogConfig {
            level: "debug".to_string(),
            format: "text".to_string(),
            file_path: None,
            include_timestamp: false,
            include_target: true,
        };
        let guard = init_logging(&config);
        assert!(guard.is_ok());
    }

    #[test]
    fn test_init_logging_json_stdout() {
        let config = LogConfig {
            level: "info".to_string(),
            format: "json".to_string(),
            file_path: None,
            include_timestamp: true,
            include_target: true,
        };
        let guard = init_logging(&config);
        assert!(guard.is_ok());
    }

    #[test]
    fn test_init_logging_invalid_level() {
        let config = LogConfig {
            level: "invalid".to_string(),
            format: "text".to_string(),
            file_path: None,
            include_timestamp: false,
            include_target: false,
        };
        let guard = init_logging(&config);
        assert!(guard.is_err());
    }

    #[test]
    fn test_log_config_defaults() {
        let config = LogConfig::default();
        assert_eq!(config.level, "info");
        assert_eq!(config.format, "json");
        assert!(config.file_path.is_none());
        assert!(config.include_timestamp);
        assert!(config.include_target);
    }

    #[test]
    fn test_security_event_macro_compiles() {
        let _ = || {
            security_event!(decision = "reject", risk = "critical", "security event");
        };
    }

    #[test]
    fn test_audit_event_macro_compiles() {
        let _ = || {
            audit_event!(action = "plugin_load", plugin = "test", "audit event");
        };
    }

    #[test]
    fn test_decision_log_macro_compiles() {
        let _ = || {
            decision_log!(pfp = "CF140000", decision = "pass", "decision");
        };
    }
}
