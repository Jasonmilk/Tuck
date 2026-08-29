//! WORM (Write Once Read Many) audit store — append-only file storage with crash recovery.
//!
//! # Design Principle
//!
//! **白盒可审计** (Core Promise #4): Audit entries are written to an
//! append-only file. Once written, entries cannot be modified or deleted
//! (WORM property). The file uses JSON Lines format (one JSON object per line)
//! for human readability and easy parsing.
//!
//! **崩溃可恢复**: On startup, the store loads all existing entries from
//! the file, rebuilding the in-memory chain. If the last line is truncated
//! (crash during write), it is discarded and the rest is loaded.
//!
//! **按需驱动**: Writes are synchronous (append to file immediately) for
//! audit integrity. For high-throughput scenarios, use the async channel
//! pattern (P4-T3 integration).
//!
//! **极致节能**: Append-only writes are efficient — no file rewriting,
//! no index maintenance. Each write is a single `write()` syscall.
//!
//! # File Format
//!
//! ```text
//! {"entry_id":"...","timestamp":...,"decision":"Pass",...,"hash":"..."}
//! {"entry_id":"...","timestamp":...,"decision":"Reject",...,"hash":"..."}
//! ...
//! ```
//!
//! Each line is a complete JSON-serialized `AuditEntry`. The file is
//! append-only — new entries are added at the end.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::audit::{AuditEntry, AuditLog, GENESIS_HASH};
use crate::Decision;

// ============================================================================
// Types
// ============================================================================

/// Audit store error.
#[derive(Debug, thiserror::Error)]
pub enum AuditStoreError {
    /// IO error.
    #[error("IO error: {0}")]
    Io(String),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(String),

    /// Chain verification failed (tampered or corrupted).
    #[error("chain verification failed at entry {index}: {reason}")]
    ChainInvalid { index: usize, reason: String },

    /// Store is not initialized (no file path).
    #[error("store not initialized")]
    NotInitialized,
}

/// Store statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreStats {
    /// Total number of entries in the store.
    pub total_entries: usize,
    /// File path.
    pub file_path: String,
    /// File size in bytes.
    pub file_size_bytes: u64,
    /// Whether the chain is valid.
    pub chain_valid: bool,
    /// Oldest entry timestamp (unix seconds).
    pub oldest_timestamp: Option<u64>,
    /// Newest entry timestamp (unix seconds).
    pub newest_timestamp: Option<u64>,
}

// ============================================================================
// Audit Store
// ============================================================================

/// WORM audit store — append-only file storage with in-memory chain.
///
/// # Usage
///
/// ```rust,ignore
/// use tuck_core::audit_store::AuditStore;
///
/// // Create or load a store
/// let store = AuditStore::new("data/audit.log").await?;
///
/// // Append a decision
/// store.append(
///     Decision::Pass,
///     "Low",
///     "Cognitive",
///     "Normal",
///     "anaphase",
///     None,
/// ).await?;
///
/// // Verify chain integrity
/// store.verify_chain().await?;
///
/// // Get stats
/// let stats = store.stats().await?;
/// ```
pub struct AuditStore {
    path: PathBuf,
    log: Mutex<AuditLog>,
}

impl AuditStore {
    /// Create a new audit store, loading existing entries from file if present.
    ///
    /// If the file doesn't exist, it is created. If it exists, all entries
    /// are loaded and the chain is verified.
    pub async fn new(path: impl Into<PathBuf>) -> Result<Self, AuditStoreError> {
        let path = path.into();
        let mut log = AuditLog::new();

        // Load existing entries if file exists
        if path.exists() {
            Self::load_from_file(&path, &mut log).await?;
        } else {
            // Create empty file
            tokio::fs::File::create(&path)
                .await
                .map_err(|e| AuditStoreError::Io(e.to_string()))?;
        }

        Ok(Self {
            path,
            log: Mutex::new(log),
        })
    }

    /// Load entries from file into the in-memory log.
    async fn load_from_file(path: &Path, log: &mut AuditLog) -> Result<(), AuditStoreError> {
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|e| AuditStoreError::Io(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut line_count = 0;
        while let Some(line) = lines
            .next_line()
            .await
            .map_err(|e| AuditStoreError::Io(e.to_string()))?
        {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            match serde_json::from_str::<AuditEntry>(line) {
                Ok(entry) => {
                    // Verify entry hash
                    if !entry.verify_hash() {
                        return Err(AuditStoreError::ChainInvalid {
                            index: line_count,
                            reason: "entry hash mismatch".to_string(),
                        });
                    }
                    // Verify prev_hash chain
                    if let Some(prev) = log.latest() {
                        if entry.prev_hash != prev.hash {
                            return Err(AuditStoreError::ChainInvalid {
                                index: line_count,
                                reason: "prev_hash mismatch".to_string(),
                            });
                        }
                    } else if entry.prev_hash != GENESIS_HASH {
                        return Err(AuditStoreError::ChainInvalid {
                            index: line_count,
                            reason: "first entry prev_hash is not GENESIS_HASH".to_string(),
                        });
                    }
                    // Entry is valid — add to log (without recomputing hash)
                    log.push_raw(entry);
                    line_count += 1;
                }
                Err(e) => {
                    // Truncated line (crash during write) — skip and stop loading
                    // The rest of the file after a truncated line is unreliable
                    eprintln!(
                        "[AuditStore] Warning: skipping truncated/corrupt line {}: {}",
                        line_count + 1,
                        e
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    /// Append a new decision to the audit log and write to file.
    ///
    /// Returns the created entry.
    pub async fn append(
        &self,
        decision: Decision,
        risk_level: &str,
        modality: &str,
        override_flag: &str,
        source: &str,
        identity_label: Option<&str>,
    ) -> Result<AuditEntry, AuditStoreError> {
        let mut log = self.log.lock().await;

        // Create entry (computes hash)
        log.append(
            decision,
            risk_level,
            modality,
            override_flag,
            source,
            identity_label,
        );
        let entry = log.latest().unwrap().clone();

        // Write to file (append mode)
        let json = serde_json::to_string(&entry)
            .map_err(|e| AuditStoreError::Json(e.to_string()))?;

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| AuditStoreError::Io(e.to_string()))?;

        file.write_all(json.as_bytes())
            .await
            .map_err(|e| AuditStoreError::Io(e.to_string()))?;
        file.write_all(b"\n")
            .await
            .map_err(|e| AuditStoreError::Io(e.to_string()))?;
        file.flush()
            .await
            .map_err(|e| AuditStoreError::Io(e.to_string()))?;

        Ok(entry)
    }

    /// Verify the entire chain integrity.
    pub async fn verify_chain(&self) -> Result<(), AuditStoreError> {
        let log = self.log.lock().await;
        log.verify_chain().map_err(|(index, reason)| {
            AuditStoreError::ChainInvalid { index, reason }
        })
    }

    /// Get the number of entries.
    pub async fn len(&self) -> usize {
        self.log.lock().await.len()
    }

    /// Check if the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.log.lock().await.is_empty()
    }

    /// Get the latest entry.
    pub async fn latest(&self) -> Option<AuditEntry> {
        self.log.lock().await.latest().cloned()
    }

    /// Get store statistics.
    pub async fn stats(&self) -> Result<StoreStats, AuditStoreError> {
        let log = self.log.lock().await;
        let file_size = tokio::fs::metadata(&self.path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        let chain_valid = log.verify_chain().is_ok();

        Ok(StoreStats {
            total_entries: log.len(),
            file_path: self.path.to_string_lossy().to_string(),
            file_size_bytes: file_size,
            chain_valid,
            oldest_timestamp: log.oldest().map(|e| e.timestamp),
            newest_timestamp: log.latest().map(|e| e.timestamp),
        })
    }

    /// Get all entries (oldest first).
    pub async fn entries(&self) -> Vec<AuditEntry> {
        let log = self.log.lock().await;
        log.iter().cloned().collect()
    }

    /// Get the file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_create_empty_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let store = AuditStore::new(&path).await.unwrap();

        assert!(store.is_empty().await);
        assert_eq!(store.len().await, 0);
        assert!(path.exists());
    }

    #[tokio::test]
    async fn test_append_and_persist() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let store = AuditStore::new(&path).await.unwrap();

        store
            .append(
                Decision::Pass,
                "Low",
                "Cognitive",
                "Normal",
                "anaphase",
                None,
            )
            .await
            .unwrap();

        assert_eq!(store.len().await, 1);

        // Verify file has content
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(!content.is_empty());
        assert!(content.contains("\"decision\":\"Pass\""));
    }

    #[tokio::test]
    async fn test_load_existing_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");

        // Create and populate
        {
            let store = AuditStore::new(&path).await.unwrap();
            store
                .append(Decision::Pass, "Low", "Cognitive", "Normal", "src1", None)
                .await
                .unwrap();
            store
                .append(Decision::Reject, "High", "Executive", "Normal", "src2", None)
                .await
                .unwrap();
        }

        // Load from file
        let store = AuditStore::new(&path).await.unwrap();
        assert_eq!(store.len().await, 2);

        let entries = store.entries().await;
        assert_eq!(entries[0].decision, "Pass");
        assert_eq!(entries[1].decision, "Reject");
        assert_eq!(entries[1].prev_hash, entries[0].hash);
    }

    #[tokio::test]
    async fn test_chain_verification() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let store = AuditStore::new(&path).await.unwrap();

        for i in 0..5 {
            store
                .append(
                    if i % 2 == 0 { Decision::Pass } else { Decision::Reject },
                    "Low",
                    "Cognitive",
                    "Normal",
                    "test",
                    None,
                )
                .await
                .unwrap();
        }

        assert!(store.verify_chain().await.is_ok());
    }

    #[tokio::test]
    async fn test_detect_tampered_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");

        // Create and populate
        {
            let store = AuditStore::new(&path).await.unwrap();
            store
                .append(Decision::Pass, "Low", "Cognitive", "Normal", "test", None)
                .await
                .unwrap();
            store
                .append(Decision::Reject, "High", "Executive", "Normal", "test", None)
                .await
                .unwrap();
        }

        // Tamper with the file: modify the first line's decision
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let tampered = content.replace("\"decision\":\"Pass\"", "\"decision\":\"Tampered\"");
        tokio::fs::write(&path, tampered).await.unwrap();

        // Loading should fail (chain verification detects tampering)
        let result = AuditStore::new(&path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_store_stats() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let store = AuditStore::new(&path).await.unwrap();

        store
            .append(Decision::Pass, "Low", "Cognitive", "Normal", "test", None)
            .await
            .unwrap();

        let stats = store.stats().await.unwrap();
        assert_eq!(stats.total_entries, 1);
        assert!(stats.chain_valid);
        assert!(stats.file_size_bytes > 0);
        assert!(stats.oldest_timestamp.is_some());
        assert!(stats.newest_timestamp.is_some());
    }

    #[tokio::test]
    async fn test_latest_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let store = AuditStore::new(&path).await.unwrap();

        assert!(store.latest().await.is_none());

        store
            .append(Decision::Pass, "Low", "Cognitive", "Normal", "src1", None)
            .await
            .unwrap();
        store
            .append(Decision::Reject, "High", "Executive", "Normal", "src2", None)
            .await
            .unwrap();

        let latest = store.latest().await.unwrap();
        assert_eq!(latest.decision, "Reject");
        assert_eq!(latest.source, "src2");
    }

    #[tokio::test]
    async fn test_append_with_identity_label() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let store = AuditStore::new(&path).await.unwrap();

        store
            .append(
                Decision::Pass,
                "Low",
                "Cognitive",
                "Normal",
                "tentacle",
                Some("env:API_KEY"),
            )
            .await
            .unwrap();

        let latest = store.latest().await.unwrap();
        assert_eq!(latest.identity_label.as_deref(), Some("env:API_KEY"));
    }

    #[tokio::test]
    async fn test_multiple_appends_chain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let store = AuditStore::new(&path).await.unwrap();

        for i in 0..20 {
            store
                .append(
                    Decision::Pass,
                    "Low",
                    "Cognitive",
                    "Normal",
                    &format!("src_{i}"),
                    None,
                )
                .await
                .unwrap();
        }

        assert_eq!(store.len().await, 20);
        assert!(store.verify_chain().await.is_ok());

        // Verify file has 20 lines
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let line_count = content.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(line_count, 20);
    }
}
