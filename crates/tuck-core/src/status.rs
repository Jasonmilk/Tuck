//! Status flow — P6-T5: Tuck decision state as a queryable snapshot.
//!
//! Cellrix (the display layer) shows Tuck's live decision state
//! (Pass / Reject / HITL / CATASTROPHIC). This module is the *window* Tuck
//! provides for that view: a pull-based, typed query interface over two
//! existing sources — no new storage, no write path, no push channel.
//!
//! # Design Principles
//!
//! **极致解耦**: `StatusProvider` is the only contract the display layer
//! depends on. Cellrix never touches `Metrics` atomics or `AuditLog` internals.
//!
//! **按需驱动**: The provider is pull-based — the display queries when it
//! needs a refresh; Tuck spends zero cycles on notification duty.
//!
//! **极致复用**: `DecisionSummary` aggregates the runtime `Metrics` counters
//! (O(1), atomic); `DecisionEvent` is a projection of recent `AuditLog`
//! entries (P4 chain). No duplicate event store is created.
//!
//! **按需加载**: `DecisionEvent` carries only the fields a display needs
//! (timestamp / decision / risk / modality / source) — the full `AuditEntry`
//! (hash chain, identity label) stays inside the audit module.

use std::fmt;

use crate::audit::AuditLog;
use crate::metrics::{DecisionCounts, Metrics, RiskCounts};

/// One projected decision event, as a display would render it.
///
/// Deliberately a thin projection of `AuditEntry`: no hash-chain fields,
/// no identity label — only what a status view needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionEvent {
    /// Unix timestamp (seconds) of the decision.
    pub timestamp: u64,
    /// Decision result (Pass / Reject / NeedHumanConfirm / HardOverridePass).
    pub decision: String,
    /// PFP Risk-Level (Low / Medium / Critical / Catastrophic).
    pub risk_level: String,
    /// PFP Modality (Cognitive / Render / Executive / SensorFeed).
    pub modality: String,
    /// Request source (e.g., "anaphase", "tentacle", "human").
    pub source: String,
}

/// Live decision snapshot — runtime cumulative counters + latest outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionSummary {
    /// Decision counters (Pass / Reject / HITL / HardOverride).
    pub decisions: DecisionCounts,
    /// Risk-level counters (Low / Medium / Critical / Catastrophic).
    pub risks: RiskCounts,
    /// Most recent decision result, if any decision has been recorded.
    pub latest_decision: Option<String>,
}

/// Pull-based status query contract for the display layer.
///
/// Implementations aggregate existing Tuck state; they never add a write
/// path or a push channel.
pub trait StatusProvider {
    /// Live cumulative snapshot (O(1), atomic reads).
    fn summary(&self) -> DecisionSummary;

    /// Most recent projected decision events, newest first, at most `limit`.
    fn recent_decisions(&self, limit: usize) -> Vec<DecisionEvent>;
}

/// Status provider over the in-memory audit chain + runtime metrics.
///
/// `AuditLog` supplies the recent-event projection; `Metrics` supplies the
/// cumulative snapshot. Both are borrowed — the provider owns nothing.
pub struct AuditStatusProvider<'a> {
    log: &'a AuditLog,
    metrics: &'a Metrics,
}

impl<'a> AuditStatusProvider<'a> {
    /// Create a provider borrowing the shared audit chain and metrics.
    pub fn new(log: &'a AuditLog, metrics: &'a Metrics) -> Self {
        Self { log, metrics }
    }
}

impl fmt::Debug for AuditStatusProvider<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditStatusProvider").finish_non_exhaustive()
    }
}

impl StatusProvider for AuditStatusProvider<'_> {
    fn summary(&self) -> DecisionSummary {
        let decisions = self.metrics.decision_counts();
        let risks = self.metrics.risk_counts();
        let latest_decision = self.log.latest().map(|e| e.decision.clone());
        DecisionSummary {
            decisions,
            risks,
            latest_decision,
        }
    }

    fn recent_decisions(&self, limit: usize) -> Vec<DecisionEvent> {
        if limit == 0 {
            return Vec::new();
        }
        // Walk the chain back-to-front (newest first) by index; `get(0)` is
        // the oldest entry, `get(n-1)` the newest.
        let n = self.log.len();
        (0..n)
            .rev()
            .take(limit)
            .filter_map(|i| self.log.get(i))
            .map(|e| DecisionEvent {
                timestamp: e.timestamp,
                decision: e.decision.clone(),
                risk_level: e.risk_level.clone(),
                modality: e.modality.clone(),
                source: e.source.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decision;

    fn append(log: &mut AuditLog, decision: Decision) {
        log.append(decision, "Low", "Executive", "Normal", "anaphase", None);
    }

    #[test]
    fn summary_aggregates_runtime_metrics() {
        let metrics = Metrics::new();
        metrics.observe_decision("Pass");
        metrics.observe_decision("Pass");
        metrics.observe_decision("Reject");
        metrics.observe_risk_level("Low");
        metrics.observe_risk_level("Low");
        metrics.observe_risk_level("Catastrophic");

        let log = AuditLog::new();
        let provider = AuditStatusProvider::new(&log, &metrics);
        let s = provider.summary();

        assert_eq!(s.decisions.pass, 2);
        assert_eq!(s.decisions.reject, 1);
        assert_eq!(s.decisions.hitl, 0);
        assert_eq!(s.decisions.hard_override, 0);
        assert_eq!(s.decisions.total(), 3);
        assert_eq!(s.risks.low, 2);
        assert_eq!(s.risks.catastrophic, 1);
        assert_eq!(s.risks.total(), 3);
        assert_eq!(s.latest_decision, None);
    }

    #[test]
    fn summary_latest_comes_from_audit_chain() {
        let metrics = Metrics::new();
        metrics.observe_decision("Pass");
        let mut log = AuditLog::new();
        append(&mut log, Decision::Reject);

        let provider = AuditStatusProvider::new(&log, &metrics);
        assert_eq!(provider.summary().latest_decision.as_deref(), Some("Reject"));
    }

    #[test]
    fn recent_projects_newest_first_and_truncates() {
        let metrics = Metrics::new();
        let mut log = AuditLog::new();
        for _ in 0..5 {
            append(&mut log, Decision::Pass);
        }
        append(&mut log, Decision::Reject);

        let provider = AuditStatusProvider::new(&log, &metrics);
        let all = provider.recent_decisions(10);
        assert_eq!(all.len(), 6);
        // Newest first: last appended is first projected.
        assert_eq!(all[0].decision, "Reject");
        assert_eq!(all[5].decision, "Pass");

        let truncated = provider.recent_decisions(2);
        assert_eq!(truncated.len(), 2);
        assert_eq!(truncated[0].decision, "Reject");
        assert_eq!(truncated[1].decision, "Pass");
    }

    #[test]
    fn recent_empty_and_zero_limit() {
        let metrics = Metrics::new();
        let log = AuditLog::new();
        let provider = AuditStatusProvider::new(&log, &metrics);

        assert!(provider.recent_decisions(10).is_empty());
        assert!(provider.recent_decisions(0).is_empty());
        let s = provider.summary();
        assert_eq!(s.decisions.total(), 0);
        assert_eq!(s.risks.total(), 0);
        assert_eq!(s.latest_decision, None);
    }

    #[test]
    fn event_projection_is_trimmed() {
        let metrics = Metrics::new();
        let mut log = AuditLog::new();
        append(&mut log, Decision::NeedHumanConfirm);

        let provider = AuditStatusProvider::new(&log, &metrics);
        let ev = &provider.recent_decisions(1)[0];
        assert_eq!(ev.decision, "NeedHumanConfirm");
        assert_eq!(ev.risk_level, "Low");
        assert_eq!(ev.modality, "Executive");
        assert_eq!(ev.source, "anaphase");
        assert!(ev.timestamp > 0);
    }

    #[test]
    fn disabled_metrics_report_zero_counts() {
        let metrics = Metrics::disabled();
        metrics.observe_decision("Pass");
        let log = AuditLog::new();
        let provider = AuditStatusProvider::new(&log, &metrics);
        let s = provider.summary();
        assert_eq!(s.decisions.total(), 0);
        assert_eq!(s.risks.total(), 0);
    }
}
