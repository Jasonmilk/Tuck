//! Audit query API — filter, paginate, and sort audit entries.
//!
//! # Design Principle
//!
//! **白盒可审计**: Audit entries are queryable by multiple dimensions:
//! time range, risk level, decision type, source, and identity label.
//! This enables security analysts to investigate specific incidents.
//!
//! **极致节能**: Queries operate on the in-memory chain (no file I/O).
//! For large datasets, use pagination to avoid loading all entries at once.
//!
//! **按需驱动**: Queries are executed on demand — no pre-computed indexes,
//! no background maintenance. Simple linear scan is sufficient for typical
//! audit log sizes (millions of entries fit in memory).

use serde::{Deserialize, Serialize};

use crate::audit::AuditEntry;

// ============================================================================
// Query Types
// ============================================================================

/// Sort order for query results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    /// Oldest first (ascending by timestamp).
    Ascending,
    /// Newest first (descending by timestamp).
    Descending,
}

impl Default for SortOrder {
    fn default() -> Self {
        Self::Descending // default: newest first
    }
}

/// Audit query — filter and pagination parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Filter by minimum timestamp (unix seconds, inclusive).
    pub from_timestamp: Option<u64>,
    /// Filter by maximum timestamp (unix seconds, inclusive).
    pub to_timestamp: Option<u64>,
    /// Filter by risk level (exact match, e.g., "Low", "Critical").
    pub risk_level: Option<String>,
    /// Filter by decision type (exact match, e.g., "Pass", "Reject").
    pub decision: Option<String>,
    /// Filter by source (exact match, e.g., "anaphase", "tentacle").
    pub source: Option<String>,
    /// Filter by identity label (substring match).
    pub identity_label_contains: Option<String>,
    /// Page offset (0-based).
    pub offset: usize,
    /// Page size (max entries to return).
    pub limit: usize,
    /// Sort order.
    pub sort: SortOrder,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            from_timestamp: None,
            to_timestamp: None,
            risk_level: None,
            decision: None,
            source: None,
            identity_label_contains: None,
            offset: 0,
            limit: 50,
            sort: SortOrder::default(),
        }
    }
}

impl AuditQuery {
    /// Create a new query with default parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set time range filter.
    pub fn with_time_range(mut self, from: u64, to: u64) -> Self {
        self.from_timestamp = Some(from);
        self.to_timestamp = Some(to);
        self
    }

    /// Set risk level filter.
    pub fn with_risk_level(mut self, level: impl Into<String>) -> Self {
        self.risk_level = Some(level.into());
        self
    }

    /// Set decision filter.
    pub fn with_decision(mut self, decision: impl Into<String>) -> Self {
        self.decision = Some(decision.into());
        self
    }

    /// Set source filter.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Set pagination.
    pub fn with_pagination(mut self, offset: usize, limit: usize) -> Self {
        self.offset = offset;
        self.limit = limit;
        self
    }

    /// Set sort order.
    pub fn with_sort(mut self, sort: SortOrder) -> Self {
        self.sort = sort;
        self
    }

    /// Check if an entry matches all filter criteria.
    fn matches(&self, entry: &AuditEntry) -> bool {
        if let Some(from) = self.from_timestamp {
            if entry.timestamp < from {
                return false;
            }
        }
        if let Some(to) = self.to_timestamp {
            if entry.timestamp > to {
                return false;
            }
        }
        if let Some(ref risk) = self.risk_level {
            if entry.risk_level != *risk {
                return false;
            }
        }
        if let Some(ref decision) = self.decision {
            if entry.decision != *decision {
                return false;
            }
        }
        if let Some(ref source) = self.source {
            if entry.source != *source {
                return false;
            }
        }
        if let Some(ref label_substr) = self.identity_label_contains {
            match &entry.identity_label {
                Some(label) => {
                    if !label.contains(label_substr) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

// ============================================================================
// Query Result
// ============================================================================

/// Paginated query result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Matching entries for this page.
    pub entries: Vec<AuditEntry>,
    /// Total number of entries matching the query (across all pages).
    pub total: usize,
    /// Current page offset.
    pub offset: usize,
    /// Page size used.
    pub limit: usize,
    /// Whether there are more pages.
    pub has_more: bool,
}

impl QueryResult {
    /// Get the number of entries in this page.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if this page is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ============================================================================
// Queryable trait
// ============================================================================

/// Trait for types that can be queried for audit entries.
///
/// Implemented for `AuditLog` and `AuditStore`.
pub trait Queryable {
    /// Execute a query and return paginated results.
    fn query(&self, query: &AuditQuery) -> QueryResult;

    /// Count entries matching a query (without pagination).
    fn count(&self, query: &AuditQuery) -> usize;
}

impl Queryable for crate::audit::AuditLog {
    fn query(&self, query: &AuditQuery) -> QueryResult {
        // Filter
        let mut matching: Vec<&AuditEntry> =
            self.iter().filter(|e| query.matches(e)).collect();

        let total = matching.len();

        // Sort
        match query.sort {
            SortOrder::Ascending => {
                matching.sort_by_key(|e| e.timestamp);
            }
            SortOrder::Descending => {
                matching.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            }
        }

        // Paginate
        let entries: Vec<AuditEntry> = matching
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .cloned()
            .collect();

        let has_more = query.offset + entries.len() < total;

        QueryResult {
            entries,
            total,
            offset: query.offset,
            limit: query.limit,
            has_more,
        }
    }

    fn count(&self, query: &AuditQuery) -> usize {
        self.iter().filter(|e| query.matches(e)).count()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;

    fn setup_log() -> AuditLog {
        use crate::audit::GENESIS_HASH;
        let mut log = AuditLog::new();

        // Helper to create an entry with a specific timestamp
        fn make_entry(
            id: u8,
            timestamp: u64,
            decision: &str,
            risk: &str,
            modality: &str,
            override_flag: &str,
            source: &str,
            label: Option<&str>,
            prev_hash: [u8; 32],
        ) -> AuditEntry {
            let mut entry = AuditEntry {
                entry_id: uuid::Uuid::from_fields(id as u32, 0, 0, &[0; 8]),
                timestamp,
                decision: decision.to_string(),
                risk_level: risk.to_string(),
                modality: modality.to_string(),
                override_flag: override_flag.to_string(),
                source: source.to_string(),
                identity_label: label.map(|s| s.to_string()),
                prev_hash,
                hash: [0u8; 32],
            };
            entry.hash = entry.compute_hash();
            entry
        }

        // Entry 0: Pass, Low, anaphase, t=1000
        let e0 = make_entry(
            0, 1000, "Pass", "Low", "Cognitive", "Normal", "anaphase", None, GENESIS_HASH,
        );
        let e0_hash = e0.hash;
        log.push_raw(e0);

        // Entry 1: Reject, Critical, tentacle, t=2000
        let e1 = make_entry(
            1, 2000, "Reject", "Critical", "Executive", "Normal", "tentacle",
            Some("env:API_KEY"), e0_hash,
        );
        let e1_hash = e1.hash;
        log.push_raw(e1);

        // Entry 2: Pass, Medium, anaphase, t=3000
        let e2 = make_entry(
            2, 3000, "Pass", "Medium", "Render", "Normal", "anaphase", None, e1_hash,
        );
        let e2_hash = e2.hash;
        log.push_raw(e2);

        // Entry 3: HardOverridePass, Catastrophic, emergency, t=4000
        let e3 = make_entry(
            3, 4000, "HardOverridePass", "Catastrophic", "Executive", "HardOverride",
            "emergency", None, e2_hash,
        );
        let e3_hash = e3.hash;
        log.push_raw(e3);

        // Entry 4: NeedHumanConfirm, High, tentacle, t=5000
        let e4 = make_entry(
            4, 5000, "NeedHumanConfirm", "High", "SensorFeed", "Normal", "tentacle",
            Some("file:/tmp/secret"), e3_hash,
        );
        log.push_raw(e4);

        log
    }

    #[test]
    fn test_query_default() {
        let log = setup_log();
        let query = AuditQuery::default();
        let result = log.query(&query);

        assert_eq!(result.total, 5);
        assert_eq!(result.len(), 5); // default limit 50, all fit
        assert!(!result.has_more);
    }

    #[test]
    fn test_query_pagination() {
        let log = setup_log();
        let query = AuditQuery::new().with_pagination(0, 2);
        let result = log.query(&query);

        assert_eq!(result.total, 5);
        assert_eq!(result.len(), 2);
        assert!(result.has_more);

        // Page 2
        let query = AuditQuery::new().with_pagination(2, 2);
        let result = log.query(&query);
        assert_eq!(result.len(), 2);
        assert!(result.has_more);

        // Page 3 (last)
        let query = AuditQuery::new().with_pagination(4, 2);
        let result = log.query(&query);
        assert_eq!(result.len(), 1);
        assert!(!result.has_more);
    }

    #[test]
    fn test_query_by_decision() {
        let log = setup_log();
        let query = AuditQuery::new().with_decision("Pass");
        let result = log.query(&query);

        assert_eq!(result.total, 2);
        assert!(result.entries.iter().all(|e| e.decision == "Pass"));
    }

    #[test]
    fn test_query_by_risk_level() {
        let log = setup_log();
        let query = AuditQuery::new().with_risk_level("Critical");
        let result = log.query(&query);

        assert_eq!(result.total, 1);
        assert_eq!(result.entries[0].risk_level, "Critical");
    }

    #[test]
    fn test_query_by_source() {
        let log = setup_log();
        let query = AuditQuery::new().with_source("tentacle");
        let result = log.query(&query);

        assert_eq!(result.total, 2);
        assert!(result.entries.iter().all(|e| e.source == "tentacle"));
    }

    #[test]
    fn test_query_by_time_range() {
        let log = setup_log();
        let query = AuditQuery::new().with_time_range(2000, 4000);
        let result = log.query(&query);

        assert_eq!(result.total, 3); // t=2000, 3000, 4000
        assert!(result
            .entries
            .iter()
            .all(|e| e.timestamp >= 2000 && e.timestamp <= 4000));
    }

    #[test]
    fn test_query_sort_ascending() {
        let log = setup_log();
        let query = AuditQuery::new().with_sort(SortOrder::Ascending);
        let result = log.query(&query);

        let timestamps: Vec<u64> = result.entries.iter().map(|e| e.timestamp).collect();
        assert_eq!(timestamps, vec![1000, 2000, 3000, 4000, 5000]);
    }

    #[test]
    fn test_query_sort_descending() {
        let log = setup_log();
        let query = AuditQuery::new().with_sort(SortOrder::Descending);
        let result = log.query(&query);

        let timestamps: Vec<u64> = result.entries.iter().map(|e| e.timestamp).collect();
        assert_eq!(timestamps, vec![5000, 4000, 3000, 2000, 1000]);
    }

    #[test]
    fn test_query_combined_filters() {
        let log = setup_log();
        let query = AuditQuery::new()
            .with_source("tentacle")
            .with_decision("Reject")
            .with_risk_level("Critical");
        let result = log.query(&query);

        assert_eq!(result.total, 1);
        assert_eq!(result.entries[0].source, "tentacle");
        assert_eq!(result.entries[0].decision, "Reject");
        assert_eq!(result.entries[0].risk_level, "Critical");
    }

    #[test]
    fn test_query_identity_label_contains() {
        let log = setup_log();
        let mut query = AuditQuery::new();
        query.identity_label_contains = Some("env:".to_string());
        let result = log.query(&query);

        assert_eq!(result.total, 1);
        assert_eq!(
            result.entries[0].identity_label.as_deref(),
            Some("env:API_KEY")
        );
    }

    #[test]
    fn test_query_no_matches() {
        let log = setup_log();
        let query = AuditQuery::new().with_source("nonexistent");
        let result = log.query(&query);

        assert_eq!(result.total, 0);
        assert!(result.is_empty());
        assert!(!result.has_more);
    }

    #[test]
    fn test_count() {
        let log = setup_log();
        let query = AuditQuery::new().with_decision("Pass");
        assert_eq!(log.count(&query), 2);

        let query = AuditQuery::new().with_source("anaphase");
        assert_eq!(log.count(&query), 2);
    }

    #[test]
    fn test_query_serialization() {
        let query = AuditQuery::new()
            .with_time_range(1000, 5000)
            .with_risk_level("High")
            .with_pagination(0, 25)
            .with_sort(SortOrder::Ascending);

        let json = serde_json::to_string(&query).unwrap();
        let parsed: AuditQuery = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.from_timestamp, Some(1000));
        assert_eq!(parsed.to_timestamp, Some(5000));
        assert_eq!(parsed.risk_level.as_deref(), Some("High"));
        assert_eq!(parsed.limit, 25);
        assert_eq!(parsed.sort, SortOrder::Ascending);
    }

    #[test]
    fn test_query_result_serialization() {
        let log = setup_log();
        let query = AuditQuery::new().with_pagination(0, 2);
        let result = log.query(&query);

        let json = serde_json::to_string(&result).unwrap();
        let parsed: QueryResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.total, 5);
        assert_eq!(parsed.len(), 2);
        assert!(parsed.has_more);
    }
}
