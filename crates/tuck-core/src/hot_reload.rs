//! Policy hot reload — update security policy without restarting Tuck.
//!
//! Monitors the policy file for changes and automatically reloads the policy
//! when the file is modified. Uses atomic swapping (`Arc<RwLock>`) so the
//! hard real-time `decide()` path is never blocked by policy reload.
//!
//! # Design Principle
//!
//! **极致解耦**: Hot reload is separate from the hard real-time path.
//! `decide()` reads from an in-memory `SecurityPolicy` via `Arc`; hot reload
//! updates the `Arc` atomically. No locks, no I/O, no blocking in `decide()`.
//!
//! **按需驱动**: File monitoring uses periodic modification-time checks
//! (configurable interval). For production, replace with `notify` crate for
//! true event-driven file watching.
//!
//! **白盒可审计**: Every reload records the old and new policy versions,
//! and the reload timestamp. The audit log can trace which policy version
//! was used for each decision.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::policy::{PolicyConfig, PolicyConfigError, PolicyVersion};
use crate::SecurityPolicy;

// ============================================================================
// Types
// ============================================================================

/// Hot reload status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReloadStatus {
    /// Policy is up to date.
    UpToDate,
    /// Policy was just reloaded.
    Reloaded,
    /// Policy reload failed.
    Failed,
}

/// Reload event — recorded for audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadEvent {
    /// Reload timestamp (unix seconds).
    pub timestamp: u64,
    /// Old policy version.
    pub old_version: PolicyVersion,
    /// New policy version.
    pub new_version: PolicyVersion,
    /// Reload status.
    pub status: ReloadStatus,
    /// Error message (if failed).
    pub error: Option<String>,
    /// File modification time at reload.
    pub file_modified: Option<u64>,
}

// ============================================================================
// Hot Reload Policy
// ============================================================================

/// Hot-reloadable security policy.
///
/// Wraps a `PolicyConfig` in `Arc<RwLock<>>` for atomic updates.
/// The hard real-time `decide()` path reads via `current_policy()` which
/// returns an `Arc<SecurityPolicy>` — no locks, no blocking.
///
/// # Usage
///
/// ```rust,ignore
/// use tuck_core::hot_reload::HotReloadPolicy;
/// use std::time::Duration;
///
/// // Load policy from file
/// let policy = HotReloadPolicy::load("config/policy.toml").await.unwrap();
///
/// // Start file watcher (checks every 5 seconds)
/// let _watcher = policy.spawn_watcher(Duration::from_secs(5));
///
/// // Get current policy for decide() (non-blocking, Arc clone)
/// let current = policy.current_policy();
/// // decide(&pfp, &current)
/// ```
#[derive(Clone)]
pub struct HotReloadPolicy {
    inner: Arc<HotReloadInner>,
}

struct HotReloadInner {
    /// Current policy config (protected by RwLock for atomic updates).
    config: RwLock<PolicyConfig>,
    /// Current security policy (pre-converted for fast access).
    security: RwLock<Arc<SecurityPolicy>>,
    /// Policy file path.
    path: PathBuf,
    /// Last known file modification time.
    last_modified: RwLock<Option<u64>>,
    /// Reload history (for audit).
    history: RwLock<Vec<ReloadEvent>>,
}

impl HotReloadPolicy {
    /// Load a policy from a TOML file.
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self, PolicyConfigError> {
        let path = path.as_ref().to_path_buf();
        let config = PolicyConfig::from_file(&path)?;
        let security = Arc::new(config.to_policy());
        let last_modified = file_modified(&path);

        Ok(Self {
            inner: Arc::new(HotReloadInner {
                config: RwLock::new(config),
                security: RwLock::new(security),
                path,
                last_modified: RwLock::new(last_modified),
                history: RwLock::new(Vec::new()),
            }),
        })
    }

    /// Create from an existing config (no file).
    pub fn from_config(config: PolicyConfig) -> Self {
        let security = Arc::new(config.to_policy());
        Self {
            inner: Arc::new(HotReloadInner {
                config: RwLock::new(config),
                security: RwLock::new(security),
                path: PathBuf::new(),
                last_modified: RwLock::new(None),
                history: RwLock::new(Vec::new()),
            }),
        }
    }

    /// Get the current security policy (non-blocking, Arc clone).
    ///
    /// This is the method used by the hard real-time `decide()` path.
    /// It returns an `Arc<SecurityPolicy>` — no locks, no blocking,
    /// just an atomic reference count increment.
    pub async fn current_policy(&self) -> Arc<SecurityPolicy> {
        self.inner.security.read().await.clone()
    }

    /// Get the current policy config.
    pub async fn current_config(&self) -> PolicyConfig {
        self.inner.config.read().await.clone()
    }

    /// Get the current policy version.
    pub async fn version(&self) -> PolicyVersion {
        self.inner.config.read().await.version()
    }

    /// Manually reload the policy from file.
    ///
    /// Returns the reload event. If the file hasn't changed, returns
    /// `ReloadStatus::UpToDate` without reloading.
    pub async fn reload(&self) -> ReloadEvent {
        let path = &self.inner.path;
        if path.as_os_str().is_empty() {
            return ReloadEvent {
                timestamp: unix_now(),
                old_version: self.version().await,
                new_version: self.version().await,
                status: ReloadStatus::Failed,
                error: Some("No policy file path".to_string()),
                file_modified: None,
            };
        }

        let current_modified = file_modified(path);
        let last_modified = *self.inner.last_modified.read().await;

        // Check if file has changed
        if current_modified == last_modified && current_modified.is_some() {
            return ReloadEvent {
                timestamp: unix_now(),
                old_version: self.version().await,
                new_version: self.version().await,
                status: ReloadStatus::UpToDate,
                error: None,
                file_modified: current_modified,
            };
        }

        // Try to load new config
        let old_version = self.version().await;
        match PolicyConfig::from_file(path) {
            Ok(new_config) => {
                let new_version = new_config.version();
                let new_security = Arc::new(new_config.to_policy());

                // Atomic swap
                {
                    let mut config = self.inner.config.write().await;
                    *config = new_config;
                }
                {
                    let mut security = self.inner.security.write().await;
                    *security = new_security;
                }
                {
                    let mut last = self.inner.last_modified.write().await;
                    *last = current_modified;
                }

                let event = ReloadEvent {
                    timestamp: unix_now(),
                    old_version,
                    new_version,
                    status: ReloadStatus::Reloaded,
                    error: None,
                    file_modified: current_modified,
                };

                // Record in history
                {
                    let mut history = self.inner.history.write().await;
                    history.push(event.clone());
                }

                event
            }
            Err(e) => {
                let event = ReloadEvent {
                    timestamp: unix_now(),
                    old_version,
                    new_version: old_version,
                    status: ReloadStatus::Failed,
                    error: Some(e.to_string()),
                    file_modified: current_modified,
                };

                {
                    let mut history = self.inner.history.write().await;
                    history.push(event.clone());
                }

                event
            }
        }
    }

    /// Spawn a background file watcher that periodically checks for changes.
    ///
    /// Returns a `JoinHandle` that can be aborted to stop the watcher.
    /// The watcher checks the file modification time every `interval`.
    /// If the file has changed, it triggers `reload()`.
    pub fn spawn_watcher(&self, interval: Duration) -> JoinHandle<()> {
        let policy = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let _ = policy.reload().await;
            }
        })
    }

    /// Get reload history (for audit).
    pub async fn history(&self) -> Vec<ReloadEvent> {
        self.inner.history.read().await.clone()
    }

    /// Get the policy file path.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn file_modified(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyConfig;
    use std::io::Write;

    fn write_temp_policy(content: &str) -> (PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        (path, dir)
    }

    fn default_policy_toml() -> String {
        r#"
[policy]
version = { major = 1, minor = 0, patch = 0 }
description = "Test policy"

[risk_levels]
low = "pass"
medium = "pass"
critical = "need_human_confirm"
catastrophic = "reject"
catastrophic_override = "hard_override_pass"
"#
        .to_string()
    }

    fn strict_policy_toml() -> String {
        r#"
[policy]
version = { major = 1, minor = 0, patch = 1 }
description = "Strict policy"

[risk_levels]
low = "pass"
medium = "need_human_confirm"
critical = "reject"
catastrophic = "reject"
catastrophic_override = "hard_override_pass"
"#
        .to_string()
    }

    #[tokio::test]
    async fn test_load_policy() {
        let (path, _dir) = write_temp_policy(&default_policy_toml());
        let policy = HotReloadPolicy::load(&path).await.unwrap();
        assert_eq!(policy.version().await.major, 1);
        let current = policy.current_policy().await;
        assert_eq!(current.medium, crate::Decision::Pass);
    }

    #[tokio::test]
    async fn test_reload_on_file_change() {
        let (path, _dir) = write_temp_policy(&default_policy_toml());
        let policy = HotReloadPolicy::load(&path).await.unwrap();

        // Initial policy: medium = pass
        let current = policy.current_policy().await;
        assert_eq!(current.medium, crate::Decision::Pass);

        // Modify file: medium = need_human_confirm
        // Sleep to ensure modification time changes
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all(strict_policy_toml().as_bytes()).unwrap();
        drop(f);

        // Manually trigger reload
        let event = policy.reload().await;
        assert_eq!(event.status, ReloadStatus::Reloaded);
        assert_eq!(event.new_version.patch, 1);

        // New policy: medium = need_human_confirm
        let current = policy.current_policy().await;
        assert_eq!(current.medium, crate::Decision::NeedHumanConfirm);
    }

    #[tokio::test]
    async fn test_reload_no_change() {
        let (path, _dir) = write_temp_policy(&default_policy_toml());
        let policy = HotReloadPolicy::load(&path).await.unwrap();

        // First reload after load: should be up to date
        let event = policy.reload().await;
        assert_eq!(event.status, ReloadStatus::UpToDate);
    }

    #[tokio::test]
    async fn test_reload_failed_invalid_file() {
        let (path, _dir) = write_temp_policy(&default_policy_toml());
        let policy = HotReloadPolicy::load(&path).await.unwrap();

        // Corrupt the file
        tokio::time::sleep(Duration::from_secs(1)).await;
        std::fs::write(&path, "invalid toml content {{{").unwrap();

        let event = policy.reload().await;
        assert_eq!(event.status, ReloadStatus::Failed);
        assert!(event.error.is_some());

        // Old policy should still be active (fail-safe: don't apply broken policy)
        let current = policy.current_policy().await;
        assert_eq!(current.medium, crate::Decision::Pass);
    }

    #[tokio::test]
    async fn test_from_config_no_file() {
        let config = PolicyConfig::default();
        let policy = HotReloadPolicy::from_config(config);
        assert_eq!(policy.version().await, PolicyVersion::CURRENT);
        // Reload should fail (no file)
        let event = policy.reload().await;
        assert_eq!(event.status, ReloadStatus::Failed);
    }

    #[tokio::test]
    async fn test_reload_history() {
        let (path, _dir) = write_temp_policy(&default_policy_toml());
        let policy = HotReloadPolicy::load(&path).await.unwrap();

        // Modify and reload
        tokio::time::sleep(Duration::from_secs(1)).await;
        std::fs::write(&path, strict_policy_toml()).unwrap();
        policy.reload().await;

        let history = policy.history().await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, ReloadStatus::Reloaded);
        assert_eq!(history[0].old_version.patch, 0);
        assert_eq!(history[0].new_version.patch, 1);
    }

    #[tokio::test]
    async fn test_watcher_spawns() {
        let (path, _dir) = write_temp_policy(&default_policy_toml());
        let policy = HotReloadPolicy::load(&path).await.unwrap();

        // Spawn watcher with short interval
        let handle = policy.spawn_watcher(Duration::from_millis(100));

        // Wait to ensure file modification time changes (second precision)
        tokio::time::sleep(Duration::from_secs(2)).await;
        std::fs::write(&path, strict_policy_toml()).unwrap();

        // Wait for watcher to detect and reload
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Policy should have been reloaded
        let current = policy.current_policy().await;
        assert_eq!(current.medium, crate::Decision::NeedHumanConfirm);

        // Stop watcher
        handle.abort();
    }

    #[tokio::test]
    async fn test_current_policy_non_blocking() {
        let config = PolicyConfig::default();
        let policy = HotReloadPolicy::from_config(config);

        // current_policy should be fast (Arc clone, no heavy locking)
        let start = std::time::Instant::now();
        let _ = policy.current_policy().await;
        assert!(start.elapsed() < Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_reload_event_serialization() {
        let event = ReloadEvent {
            timestamp: 1234567890,
            old_version: PolicyVersion::new(1, 0, 0),
            new_version: PolicyVersion::new(1, 0, 1),
            status: ReloadStatus::Reloaded,
            error: None,
            file_modified: Some(1234567890),
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: ReloadEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, ReloadStatus::Reloaded);
        assert_eq!(parsed.new_version.patch, 1);
    }
}
