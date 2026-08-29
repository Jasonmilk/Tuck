//! Audit log — SHA-256 chained, append-only, tamper-evident decision records.
//!
//! # Design Principle
//!
//! **白盒可审计** (Core Promise #4): Every decision is recorded in a
//! SHA-256 chained log. Each entry contains the hash of the previous entry,
//! making the chain tamper-evident — any modification to an old entry breaks
//! all subsequent hashes.
//!
//! **极致节能**: Audit entries are serialized as compact binary (not JSON)
//! for fast append and small file size. Hash computation uses SHA-256,
//! which is hardware-accelerated on modern CPUs.
//!
//! **按需驱动**: Audit writes are asynchronous — the hard real-time `decide()`
//! path never blocks on audit I/O. Decisions are recorded via a channel and
//! written to disk by a background task.
//!
//! # Chain Structure
//!
//! ```text
//! Genesis Entry (prev_hash = 0x00...00)
//!     ↓ hash = SHA256(prev_hash + entry_data)
//! Entry 1 (prev_hash = Genesis.hash)
//!     ↓ hash = SHA256(prev_hash + entry_data)
//! Entry 2 (prev_hash = Entry1.hash)
//!     ↓ ...
//! ```
//!
//! Any modification to Entry N changes Entry N.hash, which breaks
//! Entry N+1.prev_hash verification, and so on to the end of the chain.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::Decision;

// ============================================================================
// Types
// ============================================================================

/// Hash type (SHA-256, 32 bytes).
pub type Hash = [u8; 32];

/// Genesis hash — all zeros, used as prev_hash for the first entry.
pub const GENESIS_HASH: Hash = [0u8; 32];

/// Audit entry — a single decision record in the audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID.
    pub entry_id: Uuid,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// Decision result (Pass/Reject/NeedHumanConfirm/HardOverridePass).
    pub decision: String,
    /// PFP Risk-Level (Low/Medium/Critical/Catastrophic).
    pub risk_level: String,
    /// PFP Modality (Cognitive/Render/Executive/SensorFeed).
    pub modality: String,
    /// PFP Override-Flag (Normal/HardOverride).
    pub override_flag: String,
    /// Source of the request (e.g., "anaphase", "tentacle", "human").
    pub source: String,
    /// Identity label used for credential injection (if any).
    pub identity_label: Option<String>,
    /// Hash of the previous entry in the chain.
    pub prev_hash: Hash,
    /// Hash of this entry (SHA-256 of prev_hash + entry data).
    pub hash: Hash,
}

impl AuditEntry {
    /// Compute the hash of this entry.
    ///
    /// Hash = SHA-256(prev_hash || entry_id || timestamp || decision ||
    ///                  risk_level || modality || override_flag || source ||
    ///                  identity_label)
    pub fn compute_hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(&self.prev_hash);
        hasher.update(self.entry_id.as_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.decision.as_bytes());
        hasher.update(self.risk_level.as_bytes());
        hasher.update(self.modality.as_bytes());
        hasher.update(self.override_flag.as_bytes());
        hasher.update(self.source.as_bytes());
        if let Some(ref label) = self.identity_label {
            hasher.update(label.as_bytes());
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify that this entry's hash is correct.
    pub fn verify_hash(&self) -> bool {
        self.hash == self.compute_hash()
    }

    /// Verify that this entry's prev_hash matches the previous entry's hash.
    pub fn verify_prev(&self, prev: &AuditEntry) -> bool {
        self.prev_hash == prev.hash
    }
}

// ============================================================================
// Audit Log (in-memory chain)
// ============================================================================

/// In-memory audit log — manages the SHA-256 chained entry list.
///
/// This is the core data structure. Persistence (WORM file storage) is
/// handled by `AuditStore` (P4-T2). Querying is handled by `AuditQuery`
/// (P4-T3).
#[derive(Debug, Clone)]
pub struct AuditLog {
    entries: VecDeque<AuditEntry>,
    /// Maximum number of entries to keep in memory (oldest are dropped).
    /// None = unlimited.
    max_entries: Option<usize>,
}

impl AuditLog {
    /// Create a new empty audit log.
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries: None,
        }
    }

    /// Create a new audit log with a maximum in-memory entry count.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries),
            max_entries: Some(max_entries),
        }
    }

    /// Append a new decision to the audit log.
    ///
    /// Automatically computes the chain hash (prev_hash = last entry's hash,
    /// or GENESIS_HASH if this is the first entry).
    pub fn append(
        &mut self,
        decision: Decision,
        risk_level: &str,
        modality: &str,
        override_flag: &str,
        source: &str,
        identity_label: Option<&str>,
    ) -> &AuditEntry {
        let prev_hash = self
            .entries
            .back()
            .map(|e| e.hash)
            .unwrap_or(GENESIS_HASH);

        let mut entry = AuditEntry {
            entry_id: Uuid::new_v4(),
            timestamp: unix_now(),
            decision: format!("{:?}", decision),
            risk_level: risk_level.to_string(),
            modality: modality.to_string(),
            override_flag: override_flag.to_string(),
            source: source.to_string(),
            identity_label: identity_label.map(|s| s.to_string()),
            prev_hash,
            hash: [0u8; 32], // placeholder, computed below
        };

        entry.hash = entry.compute_hash();
        self.entries.push_back(entry);

        // Enforce max_entries (drop oldest)
        if let Some(max) = self.max_entries {
            while self.entries.len() > max {
                self.entries.pop_front();
            }
        }

        self.entries.back().unwrap()
    }

    /// Get the number of entries in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the latest entry (most recent).
    pub fn latest(&self) -> Option<&AuditEntry> {
        self.entries.back()
    }

    /// Get the oldest entry in memory.
    pub fn oldest(&self) -> Option<&AuditEntry> {
        self.entries.front()
    }

    /// Get an entry by index (0 = oldest in memory).
    pub fn get(&self, index: usize) -> Option<&AuditEntry> {
        self.entries.get(index)
    }

    /// Iterate over all entries (oldest first).
    pub fn iter(&self) -> impl Iterator<Item = &AuditEntry> {
        self.entries.iter()
    }

    /// Verify the entire chain integrity.
    ///
    /// Checks:
    /// 1. Each entry's hash is correct (compute_hash == stored hash)
    /// 2. Each entry's prev_hash matches the previous entry's hash
    /// 3. The first entry's prev_hash is GENESIS_HASH
    ///
    /// Returns Ok(()) if valid, Err((index, reason)) if invalid.
    pub fn verify_chain(&self) -> Result<(), (usize, String)> {
        let mut prev_hash: Option<Hash> = None;

        for (i, entry) in self.entries.iter().enumerate() {
            // Check 1: hash is correct
            if !entry.verify_hash() {
                return Err((i, format!("entry {} hash mismatch", i)));
            }

            // Check 2: prev_hash matches previous entry
            if let Some(prev) = prev_hash {
                if entry.prev_hash != prev {
                    return Err((i, format!("entry {} prev_hash mismatch", i)));
                }
            } else {
                // Check 3: first entry's prev_hash is GENESIS_HASH
                if entry.prev_hash != GENESIS_HASH {
                    return Err((i, "first entry prev_hash is not GENESIS_HASH".to_string()));
                }
            }

            prev_hash = Some(entry.hash);
        }

        Ok(())
    }

    /// Clear all entries from memory (does NOT delete persisted entries).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Push a pre-computed entry (used when loading from file).
    ///
    /// Unlike `append()`, this does NOT compute the hash — it assumes the
    /// entry already has a valid hash and prev_hash. Used for crash recovery.
    pub fn push_raw(&mut self, entry: AuditEntry) {
        self.entries.push_back(entry);

        // Enforce max_entries (drop oldest)
        if let Some(max) = self.max_entries {
            while self.entries.len() > max {
                self.entries.pop_front();
            }
        }
    }

    /// Get a mutable reference to an entry by index (for testing/tamper detection).
    ///
    /// # Warning
    ///
    /// Modifying an entry through this method will break the hash chain.
    /// This is intended for testing tamper detection only.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut AuditEntry> {
        self.entries.get_mut(index)
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper
// ============================================================================

fn unix_now() -> u64 {
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
    fn test_audit_log_empty() {
        let log = AuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.latest().is_none());
        assert!(log.oldest().is_none());
    }

    #[test]
    fn test_append_first_entry() {
        let mut log = AuditLog::new();
        log.append(
            Decision::Pass,
            "Low",
            "Cognitive",
            "Normal",
            "anaphase",
            None,
        );

        assert_eq!(log.len(), 1);
        let entry = log.latest().unwrap();
        assert_eq!(entry.prev_hash, GENESIS_HASH);
        assert!(entry.verify_hash());
        assert_eq!(entry.decision, "Pass");
        assert_eq!(entry.risk_level, "Low");
    }

    #[test]
    fn test_append_multiple_entries_chain() {
        let mut log = AuditLog::new();

        log.append(
            Decision::Pass,
            "Low",
            "Cognitive",
            "Normal",
            "anaphase",
            None,
        );
        let e1_hash = log.latest().unwrap().hash;

        log.append(
            Decision::Reject,
            "Critical",
            "Executive",
            "Normal",
            "tentacle",
            Some("env:API_KEY"),
        );

        assert_eq!(log.len(), 2);
        let e2 = log.latest().unwrap();
        assert_eq!(e2.prev_hash, e1_hash);
        assert!(e2.verify_hash());
        assert_eq!(e2.decision, "Reject");
        assert_eq!(e2.identity_label.as_deref(), Some("env:API_KEY"));
    }

    #[test]
    fn test_verify_chain_valid() {
        let mut log = AuditLog::new();
        for i in 0..10 {
            log.append(
                if i % 2 == 0 { Decision::Pass } else { Decision::Reject },
                "Low",
                "Cognitive",
                "Normal",
                "test",
                None,
            );
        }

        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn test_verify_chain_tampered_hash() {
        let mut log = AuditLog::new();
        log.append(Decision::Pass, "Low", "Cognitive", "Normal", "test", None);
        log.append(Decision::Reject, "High", "Executive", "Normal", "test", None);

        // Tamper with the first entry's decision (changes its hash)
        log.entries[0].decision = "Tampered".to_string();

        let result = log.verify_chain();
        assert!(result.is_err());
        let (index, _) = result.unwrap_err();
        assert_eq!(index, 0); // first entry fails hash verification
    }

    #[test]
    fn test_verify_chain_tampered_prev_hash() {
        let mut log = AuditLog::new();
        log.append(Decision::Pass, "Low", "Cognitive", "Normal", "test", None);
        log.append(Decision::Reject, "High", "Executive", "Normal", "test", None);
        log.append(Decision::Pass, "Low", "Cognitive", "Normal", "test", None);

        // Tamper with the second entry's prev_hash (break the chain link)
        log.entries[1].prev_hash = [0xFFu8; 32];

        let result = log.verify_chain();
        assert!(result.is_err());
        let (index, _) = result.unwrap_err();
        assert_eq!(index, 1); // second entry fails prev_hash verification
    }

    #[test]
    fn test_verify_chain_first_entry_not_genesis() {
        let mut log = AuditLog::new();
        log.append(Decision::Pass, "Low", "Cognitive", "Normal", "test", None);

        // Tamper with first entry's prev_hash
        log.entries[0].prev_hash = [0xAAu8; 32];

        let result = log.verify_chain();
        assert!(result.is_err());
    }

    #[test]
    fn test_max_entries_capacity() {
        let mut log = AuditLog::with_capacity(5);
        for i in 0..10 {
            log.append(
                Decision::Pass,
                "Low",
                "Cognitive",
                "Normal",
                &format!("source_{i}"),
                None,
            );
        }

        assert_eq!(log.len(), 5);
        // Oldest should be entry 5 (0-indexed), entries 0-4 were dropped
        assert_eq!(log.oldest().unwrap().source, "source_5");
        assert_eq!(log.latest().unwrap().source, "source_9");
    }

    #[test]
    fn test_entry_hash_deterministic() {
        let entry = AuditEntry {
            entry_id: Uuid::nil(),
            timestamp: 1234567890,
            decision: "Pass".to_string(),
            risk_level: "Low".to_string(),
            modality: "Cognitive".to_string(),
            override_flag: "Normal".to_string(),
            source: "test".to_string(),
            identity_label: None,
            prev_hash: GENESIS_HASH,
            hash: [0u8; 32],
        };

        let hash1 = entry.compute_hash();
        let hash2 = entry.compute_hash();
        assert_eq!(hash1, hash2); // deterministic
    }

    #[test]
    fn test_entry_hash_changes_with_data() {
        let mut entry = AuditEntry {
            entry_id: Uuid::nil(),
            timestamp: 1234567890,
            decision: "Pass".to_string(),
            risk_level: "Low".to_string(),
            modality: "Cognitive".to_string(),
            override_flag: "Normal".to_string(),
            source: "test".to_string(),
            identity_label: None,
            prev_hash: GENESIS_HASH,
            hash: [0u8; 32],
        };

        let hash1 = entry.compute_hash();
        entry.decision = "Reject".to_string();
        let hash2 = entry.compute_hash();
        assert_ne!(hash1, hash2); // different data = different hash
    }

    #[test]
    fn test_entry_serialization() {
        let mut log = AuditLog::new();
        log.append(
            Decision::HardOverridePass,
            "Catastrophic",
            "Executive",
            "HardOverride",
            "emergency",
            None,
        );

        let entry = log.latest().unwrap();
        let json = serde_json::to_string(entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entry_id, entry.entry_id);
        assert_eq!(parsed.hash, entry.hash);
        assert_eq!(parsed.decision, "HardOverridePass");
    }

    #[test]
    fn test_iter_entries() {
        let mut log = AuditLog::new();
        for i in 0..5 {
            log.append(
                Decision::Pass,
                "Low",
                "Cognitive",
                "Normal",
                &format!("src_{i}"),
                None,
            );
        }

        let sources: Vec<&str> = log.iter().map(|e| e.source.as_str()).collect();
        assert_eq!(sources, vec!["src_0", "src_1", "src_2", "src_3", "src_4"]);
    }

    #[test]
    fn test_clear_log() {
        let mut log = AuditLog::new();
        log.append(Decision::Pass, "Low", "Cognitive", "Normal", "test", None);
        log.append(Decision::Reject, "High", "Executive", "Normal", "test", None);
        assert_eq!(log.len(), 2);

        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn test_genesis_hash_constant() {
        assert_eq!(GENESIS_HASH, [0u8; 32]);
        assert_eq!(GENESIS_HASH.len(), 32);
    }
}
