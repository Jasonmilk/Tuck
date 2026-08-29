//! Tamper detection — detailed chain integrity verification with reports.
//!
//! # Design Principle
//!
//! **白盒可审计** (Core Promise #4): The audit chain is tamper-evident.
//! Any modification to an existing entry breaks the hash chain. This module
//! provides detailed tamper reports that identify exactly where and how the
//! chain was tampered.
//!
//! **物理事实优先**: Tamper detection is based on cryptographic hashes
//! (SHA-256), not on trust. If the hashes don't match, the chain is tampered.
//!
//! **极致节能**: Tamper detection is a single linear scan of the chain.
//! No complex data structures, no background processes.

use serde::{Deserialize, Serialize};

use crate::audit::{AuditEntry, AuditLog, GENESIS_HASH};
use crate::catastrophic::CatastrophicEvent;
use crate::hitl::ConfirmRequest;
use crate::hot_reload::ReloadEvent;

// ============================================================================
// Tamper Types
// ============================================================================

/// Type of tampering detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperType {
    /// Entry's stored hash doesn't match computed hash (entry was modified).
    HashMismatch,
    /// Entry's prev_hash doesn't match previous entry's hash (chain was broken).
    PrevHashMismatch,
    /// First entry's prev_hash is not GENESIS_HASH (chain start was tampered).
    MissingGenesis,
    /// Gap in entry IDs (entry was deleted).
    EntryDeleted,
    /// Duplicate entry ID (entry was inserted).
    DuplicateEntryId,
}

impl std::fmt::Display for TamperType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashMismatch => write!(f, "hash_mismatch"),
            Self::PrevHashMismatch => write!(f, "prev_hash_mismatch"),
            Self::MissingGenesis => write!(f, "missing_genesis"),
            Self::EntryDeleted => write!(f, "entry_deleted"),
            Self::DuplicateEntryId => write!(f, "duplicate_entry_id"),
        }
    }
}

/// Single tamper finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperFinding {
    /// Index in the chain where tampering was detected.
    pub index: usize,
    /// Type of tampering.
    pub tamper_type: TamperType,
    /// Human-readable description.
    pub description: String,
    /// Entry ID at this index (if available).
    pub entry_id: Option<String>,
}

/// Tamper detection report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperReport {
    /// Whether the chain is valid (no tampering detected).
    pub is_valid: bool,
    /// Total number of entries scanned.
    pub entries_scanned: usize,
    /// List of tamper findings (empty if valid).
    pub findings: Vec<TamperFinding>,
    /// Timestamp of detection (unix seconds).
    pub detected_at: u64,
}

impl TamperReport {
    /// Create a valid (no tampering) report.
    pub fn valid(entries_scanned: usize) -> Self {
        Self {
            is_valid: true,
            entries_scanned,
            findings: Vec::new(),
            detected_at: unix_now(),
        }
    }

    /// Create a report with findings.
    pub fn with_findings(entries_scanned: usize, findings: Vec<TamperFinding>) -> Self {
        Self {
            is_valid: findings.is_empty(),
            entries_scanned,
            findings,
            detected_at: unix_now(),
        }
    }

    /// Get the number of findings.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Check if a specific tamper type was found.
    pub fn has_type(&self, tamper_type: TamperType) -> bool {
        self.findings.iter().any(|f| f.tamper_type == tamper_type)
    }
}

// ============================================================================
// Tamper Detection
// ============================================================================

/// Detect tampering in an audit log chain.
///
/// Performs comprehensive checks:
/// 1. Each entry's hash is correct (compute_hash == stored hash)
/// 2. Each entry's prev_hash matches the previous entry's hash
/// 3. First entry's prev_hash is GENESIS_HASH
/// 4. No duplicate entry IDs
///
/// Returns a detailed `TamperReport`.
pub fn detect_tampering(log: &AuditLog) -> TamperReport {
    let mut findings = Vec::new();
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut seen_ids = std::collections::HashSet::new();

    for (i, entry) in log.iter().enumerate() {
        // Check 1: hash is correct
        if !entry.verify_hash() {
            findings.push(TamperFinding {
                index: i,
                tamper_type: TamperType::HashMismatch,
                description: format!(
                    "entry {} stored hash doesn't match computed hash (entry was modified)",
                    i
                ),
                entry_id: Some(entry.entry_id.to_string()),
            });
        }

        // Check 2: prev_hash matches previous entry
        if let Some(prev) = prev_hash {
            if entry.prev_hash != prev {
                findings.push(TamperFinding {
                    index: i,
                    tamper_type: TamperType::PrevHashMismatch,
                    description: format!(
                        "entry {} prev_hash doesn't match previous entry's hash (chain was broken)",
                        i
                    ),
                    entry_id: Some(entry.entry_id.to_string()),
                });
            }
        } else {
            // Check 3: first entry's prev_hash is GENESIS_HASH
            if entry.prev_hash != GENESIS_HASH {
                findings.push(TamperFinding {
                    index: i,
                    tamper_type: TamperType::MissingGenesis,
                    description: "first entry's prev_hash is not GENESIS_HASH (chain start was tampered)".to_string(),
                    entry_id: Some(entry.entry_id.to_string()),
                });
            }
        }

        // Check 4: no duplicate entry IDs
        if !seen_ids.insert(entry.entry_id) {
            findings.push(TamperFinding {
                index: i,
                tamper_type: TamperType::DuplicateEntryId,
                description: format!(
                    "entry {} has duplicate entry ID {} (entry was inserted)",
                    i, entry.entry_id
                ),
                entry_id: Some(entry.entry_id.to_string()),
            });
        }

        prev_hash = Some(entry.hash);
    }

    TamperReport::with_findings(log.len(), findings)
}

// ============================================================================
// History Integration
// ============================================================================

/// Convert a HITL confirm request to an audit entry.
///
/// This allows HITL events to be recorded in the audit chain.
pub fn hitl_to_audit_entry(
    request: &ConfirmRequest,
    prev_hash: [u8; 32],
) -> AuditEntry {
    let mut entry = AuditEntry {
        entry_id: request.id,
        timestamp: request.created_at,
        decision: format!("NeedHumanConfirm:{:?}", request.status),
        risk_level: "Medium".to_string(), // HITL is always Medium risk
        modality: "Cognitive".to_string(),
        override_flag: "Normal".to_string(),
        source: "hitl".to_string(),
        identity_label: None,
        prev_hash,
        hash: [0u8; 32],
    };
    entry.hash = entry.compute_hash();
    entry
}

/// Convert a CATASTROPHIC event to an audit entry.
pub fn catastrophic_to_audit_entry(
    event: &CatastrophicEvent,
    prev_hash: [u8; 32],
) -> AuditEntry {
    let mut entry = AuditEntry {
        entry_id: event.id,
        timestamp: event.created_at,
        decision: "HardOverridePass".to_string(),
        risk_level: event.risk_level.clone(),
        modality: event.modality.clone(),
        override_flag: event.override_flag.clone(),
        source: "catastrophic".to_string(),
        identity_label: None,
        prev_hash,
        hash: [0u8; 32],
    };
    entry.hash = entry.compute_hash();
    entry
}

/// Convert a policy reload event to an audit entry.
pub fn reload_to_audit_entry(
    event: &ReloadEvent,
    prev_hash: [u8; 32],
) -> AuditEntry {
    let decision = match event.status {
        crate::hot_reload::ReloadStatus::Reloaded => "PolicyReloaded",
        crate::hot_reload::ReloadStatus::UpToDate => "PolicyUpToDate",
        crate::hot_reload::ReloadStatus::Failed => "PolicyReloadFailed",
    };

    let mut entry = AuditEntry {
        entry_id: uuid::Uuid::new_v4(),
        timestamp: event.timestamp,
        decision: decision.to_string(),
        risk_level: "Low".to_string(),
        modality: "Cognitive".to_string(),
        override_flag: "Normal".to_string(),
        source: "policy_reload".to_string(),
        identity_label: None,
        prev_hash,
        hash: [0u8; 32],
    };
    entry.hash = entry.compute_hash();
    entry
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
    use crate::audit::AuditLog;
    use crate::Decision;

    fn setup_valid_log() -> AuditLog {
        let mut log = AuditLog::new();
        for i in 0..5 {
            log.append(
                if i % 2 == 0 {
                    Decision::Pass
                } else {
                    Decision::Reject
                },
                "Low",
                "Cognitive",
                "Normal",
                "test",
                None,
            );
        }
        log
    }

    #[test]
    fn test_detect_no_tampering() {
        let log = setup_valid_log();
        let report = detect_tampering(&log);

        assert!(report.is_valid);
        assert_eq!(report.entries_scanned, 5);
        assert_eq!(report.finding_count(), 0);
    }

    #[test]
    fn test_detect_hash_mismatch() {
        let mut log = setup_valid_log();
        // Tamper with entry 2's decision (changes its hash)
        log.get_mut(2).unwrap().decision = "Tampered".to_string();

        let report = detect_tampering(&log);
        assert!(!report.is_valid);
        assert!(report.has_type(TamperType::HashMismatch));
        assert_eq!(report.findings[0].index, 2);
    }

    #[test]
    fn test_detect_prev_hash_mismatch() {
        let mut log = setup_valid_log();
        // Tamper with entry 1's prev_hash (break the chain link)
        log.get_mut(1).unwrap().prev_hash = [0xFFu8; 32];

        let report = detect_tampering(&log);
        assert!(!report.is_valid);
        assert!(report.has_type(TamperType::PrevHashMismatch));
        assert_eq!(report.findings[0].index, 1);
    }

    #[test]
    fn test_detect_missing_genesis() {
        let mut log = setup_valid_log();
        // Tamper with first entry's prev_hash
        log.get_mut(0).unwrap().prev_hash = [0xAAu8; 32];

        let report = detect_tampering(&log);
        assert!(!report.is_valid);
        assert!(report.has_type(TamperType::MissingGenesis));
    }

    #[test]
    fn test_detect_duplicate_entry_id() {
        let mut log = setup_valid_log();
        // Duplicate entry 0's ID in entry 3
        let id0 = log.get(0).unwrap().entry_id;
        log.get_mut(3).unwrap().entry_id = id0;

        let report = detect_tampering(&log);
        assert!(!report.is_valid);
        assert!(report.has_type(TamperType::DuplicateEntryId));
    }

    #[test]
    fn test_multiple_tamper_findings() {
        let mut log = setup_valid_log();
        // Tamper multiple entries
        log.get_mut(1).unwrap().decision = "Tampered1".to_string();
        log.get_mut(3).unwrap().decision = "Tampered3".to_string();

        let report = detect_tampering(&log);
        assert!(!report.is_valid);
        assert!(report.finding_count() >= 2); // at least 2 hash mismatches
    }

    #[test]
    fn test_tamper_report_serialization() {
        let log = setup_valid_log();
        let report = detect_tampering(&log);

        let json = serde_json::to_string(&report).unwrap();
        let parsed: TamperReport = serde_json::from_str(&json).unwrap();

        assert!(parsed.is_valid);
        assert_eq!(parsed.entries_scanned, 5);
    }

    #[test]
    fn test_tamper_type_display() {
        assert_eq!(TamperType::HashMismatch.to_string(), "hash_mismatch");
        assert_eq!(
            TamperType::PrevHashMismatch.to_string(),
            "prev_hash_mismatch"
        );
        assert_eq!(TamperType::MissingGenesis.to_string(), "missing_genesis");
        assert_eq!(TamperType::EntryDeleted.to_string(), "entry_deleted");
        assert_eq!(
            TamperType::DuplicateEntryId.to_string(),
            "duplicate_entry_id"
        );
    }

    #[test]
    fn test_empty_log_is_valid() {
        let log = AuditLog::new();
        let report = detect_tampering(&log);

        assert!(report.is_valid);
        assert_eq!(report.entries_scanned, 0);
        assert_eq!(report.finding_count(), 0);
    }

    #[test]
    fn test_hitl_to_audit_entry() {
        use crate::hitl::{ConfirmRequest, ConfirmStatus};

        let request = ConfirmRequest {
            id: uuid::Uuid::new_v4(),
            risk_level: "Medium".to_string(),
            modality: "Cognitive".to_string(),
            description: "test request".to_string(),
            created_at: 1234567890,
            timeout_secs: 300,
            status: ConfirmStatus::Pending,
        };

        let entry = hitl_to_audit_entry(&request, GENESIS_HASH);
        assert!(entry.verify_hash());
        assert_eq!(entry.source, "hitl");
        assert_eq!(entry.timestamp, 1234567890);
        assert!(entry.decision.contains("NeedHumanConfirm"));
    }

    #[test]
    fn test_catastrophic_to_audit_entry() {
        use crate::catastrophic::{CatastrophicEvent, CatastrophicStatus};

        let event = CatastrophicEvent {
            id: uuid::Uuid::new_v4(),
            risk_level: "Catastrophic".to_string(),
            modality: "Executive".to_string(),
            override_flag: "HardOverride".to_string(),
            description: "emergency".to_string(),
            created_at: 1234567890,
            humans_notified: true,
            status: CatastrophicStatus::Triggered,
        };

        let entry = catastrophic_to_audit_entry(&event, GENESIS_HASH);
        assert!(entry.verify_hash());
        assert_eq!(entry.source, "catastrophic");
        assert_eq!(entry.decision, "HardOverridePass");
        assert_eq!(entry.risk_level, "Catastrophic");
    }

    #[test]
    fn test_reload_to_audit_entry() {
        use crate::hot_reload::{ReloadEvent, ReloadStatus};
        use crate::policy::PolicyVersion;

        let event = ReloadEvent {
            timestamp: 1234567890,
            old_version: PolicyVersion::new(1, 0, 0),
            new_version: PolicyVersion::new(1, 0, 1),
            status: ReloadStatus::Reloaded,
            error: None,
            file_modified: Some(1234567890),
        };

        let entry = reload_to_audit_entry(&event, GENESIS_HASH);
        assert!(entry.verify_hash());
        assert_eq!(entry.source, "policy_reload");
        assert_eq!(entry.decision, "PolicyReloaded");
    }

    #[test]
    fn test_history_integration_chain() {
        // Verify that converted history entries form a valid chain
        use crate::hitl::{ConfirmRequest, ConfirmStatus};

        let mut log = AuditLog::new();

        // Add a regular decision
        log.append(Decision::Pass, "Low", "Cognitive", "Normal", "anaphase", None);
        let prev_hash = log.latest().unwrap().hash;

        // Add a HITL event
        let request = ConfirmRequest {
            id: uuid::Uuid::new_v4(),
            risk_level: "Medium".to_string(),
            modality: "Cognitive".to_string(),
            description: "test".to_string(),
            created_at: 1000,
            timeout_secs: 300,
            status: ConfirmStatus::Pending,
        };
        let hitl_entry = hitl_to_audit_entry(&request, prev_hash);
        log.push_raw(hitl_entry);

        // Verify chain is valid
        let report = detect_tampering(&log);
        assert!(report.is_valid);
        assert_eq!(log.len(), 2);
    }
}
