//! Tuck Prometheus metrics.
//!
//! # Design Principle
//!
//! **极致节能**: Metrics use atomic counters (no locks, no heap allocation
//! in the hot path). `observe_decision()` is a single atomic increment —
//! sub-nanosecond overhead.
//!
//! **白盒可观测**: All metrics are exposed in Prometheus text format at
//! `/metrics`. Includes decision counters, latency histograms, error rates,
//! and credential injection success rates.
//!
//! **按需加载**: Metrics are only collected when enabled in config. When
//! disabled, all metric operations are no-ops (checked at initialization).
//!
//! **确定性优先**: Metric names and labels are fixed at compile time.
//! No dynamic label creation, no metric explosion.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

// ============================================================================
// Metrics Registry
// ============================================================================

/// Structured decision-counter snapshot (runtime cumulative).
///
/// Read-side projection of the four decision atomics. P6-T5 status flow
/// consumes this instead of the raw atomics (encapsulation + typed reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionCounts {
    /// Allow decisions.
    pub pass: u64,
    /// Deny decisions.
    pub reject: u64,
    /// Human-in-the-loop pending decisions.
    pub hitl: u64,
    /// Hard-override pass decisions.
    pub hard_override: u64,
}

impl DecisionCounts {
    /// Total decisions observed.
    pub fn total(&self) -> u64 {
        self.pass + self.reject + self.hitl + self.hard_override
    }
}

/// Structured risk-level counter snapshot (runtime cumulative).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskCounts {
    /// Low-risk decisions.
    pub low: u64,
    /// Medium-risk decisions.
    pub medium: u64,
    /// Critical-risk decisions.
    pub critical: u64,
    /// Catastrophic-risk decisions.
    pub catastrophic: u64,
}

impl RiskCounts {
    /// Total risk observations.
    pub fn total(&self) -> u64 {
        self.low + self.medium + self.critical + self.catastrophic
    }
}

/// Tuck metrics registry — all metrics are atomic counters/gauges.
///
/// Cloning is cheap (Arc internally). Pass by value to handlers.
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
    enabled: bool,
}

#[derive(Debug)]
struct MetricsInner {
    // Decision counters
    decisions_pass: AtomicU64,
    decisions_reject: AtomicU64,
    decisions_hitl: AtomicU64,
    decisions_hard_override: AtomicU64,

    // Risk level counters
    risk_low: AtomicU64,
    risk_medium: AtomicU64,
    risk_critical: AtomicU64,
    risk_catastrophic: AtomicU64,

    // Latency (nanoseconds, accumulated)
    decision_latency_ns_total: AtomicU64,
    decision_latency_count: AtomicU64,

    // Credential injection
    credential_injections_success: AtomicU64,
    credential_injections_failed: AtomicU64,
    credential_lookups_total: AtomicU64,
    credential_lookups_miss: AtomicU64,

    // Audit
    audit_entries_written: AtomicU64,
    audit_chain_verifications: AtomicU64,
    audit_chain_failures: AtomicU64,

    // SAP / replay protection
    sap_verifications_total: AtomicU64,
    sap_verifications_failed: AtomicU64,
    replay_cache_hits: AtomicU64,
    replay_cache_misses: AtomicU64,

    // Plugin audit
    plugin_audits_total: AtomicU64,
    plugin_audits_pass: AtomicU64,
    plugin_audits_reject: AtomicU64,
    plugin_audits_hitl: AtomicU64,

    // Errors
    invalid_pfp: AtomicU64,
    invalid_sap: AtomicU64,
    config_errors: AtomicU64,

    // Uptime
    start_time: Instant,
}

impl Default for MetricsInner {
    fn default() -> Self {
        Self {
            decisions_pass: AtomicU64::new(0),
            decisions_reject: AtomicU64::new(0),
            decisions_hitl: AtomicU64::new(0),
            decisions_hard_override: AtomicU64::new(0),
            risk_low: AtomicU64::new(0),
            risk_medium: AtomicU64::new(0),
            risk_critical: AtomicU64::new(0),
            risk_catastrophic: AtomicU64::new(0),
            decision_latency_ns_total: AtomicU64::new(0),
            decision_latency_count: AtomicU64::new(0),
            credential_injections_success: AtomicU64::new(0),
            credential_injections_failed: AtomicU64::new(0),
            credential_lookups_total: AtomicU64::new(0),
            credential_lookups_miss: AtomicU64::new(0),
            audit_entries_written: AtomicU64::new(0),
            audit_chain_verifications: AtomicU64::new(0),
            audit_chain_failures: AtomicU64::new(0),
            sap_verifications_total: AtomicU64::new(0),
            sap_verifications_failed: AtomicU64::new(0),
            replay_cache_hits: AtomicU64::new(0),
            replay_cache_misses: AtomicU64::new(0),
            plugin_audits_total: AtomicU64::new(0),
            plugin_audits_pass: AtomicU64::new(0),
            plugin_audits_reject: AtomicU64::new(0),
            plugin_audits_hitl: AtomicU64::new(0),
            invalid_pfp: AtomicU64::new(0),
            invalid_sap: AtomicU64::new(0),
            config_errors: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
}

impl Metrics {
    /// Create a new metrics registry (enabled).
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsInner::default()),
            enabled: true,
        }
    }

    /// Create a disabled metrics registry (all operations are no-ops).
    pub fn disabled() -> Self {
        Self {
            inner: Arc::new(MetricsInner::default()),
            enabled: false,
        }
    }

    /// Check if metrics are enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    // ========================================================================
    // Decision metrics
    // ========================================================================

    /// Observe a decision (increments the appropriate counter).
    pub fn observe_decision(&self, decision: &str) {
        if !self.enabled {
            return;
        }
        match decision {
            "Pass" => self.inner.decisions_pass.fetch_add(1, Ordering::Relaxed),
            "Reject" => self.inner.decisions_reject.fetch_add(1, Ordering::Relaxed),
            "NeedHumanConfirm" => self.inner.decisions_hitl.fetch_add(1, Ordering::Relaxed),
            "HardOverridePass" => self.inner.decisions_hard_override.fetch_add(1, Ordering::Relaxed),
            _ => return,
        };
    }

    /// Observe a risk level.
    pub fn observe_risk_level(&self, risk: &str) {
        if !self.enabled {
            return;
        }
        match risk {
            "Low" => self.inner.risk_low.fetch_add(1, Ordering::Relaxed),
            "Medium" => self.inner.risk_medium.fetch_add(1, Ordering::Relaxed),
            "Critical" => self.inner.risk_critical.fetch_add(1, Ordering::Relaxed),
            "Catastrophic" => self.inner.risk_catastrophic.fetch_add(1, Ordering::Relaxed),
            _ => return,
        };
    }

    /// Snapshot of decision counters (runtime cumulative).
    ///
    /// Read-side projection used by the P6-T5 status flow. Consistent with
    /// the observe path: disabled metrics report zero counts.
    pub fn decision_counts(&self) -> DecisionCounts {
        DecisionCounts {
            pass: self.inner.decisions_pass.load(Ordering::Relaxed),
            reject: self.inner.decisions_reject.load(Ordering::Relaxed),
            hitl: self.inner.decisions_hitl.load(Ordering::Relaxed),
            hard_override: self.inner.decisions_hard_override.load(Ordering::Relaxed),
        }
    }

    /// Snapshot of risk-level counters (runtime cumulative).
    pub fn risk_counts(&self) -> RiskCounts {
        RiskCounts {
            low: self.inner.risk_low.load(Ordering::Relaxed),
            medium: self.inner.risk_medium.load(Ordering::Relaxed),
            critical: self.inner.risk_critical.load(Ordering::Relaxed),
            catastrophic: self.inner.risk_catastrophic.load(Ordering::Relaxed),
        }
    }

    /// Observe decision latency.
    pub fn observe_decision_latency(&self, duration_ns: u64) {        if !self.enabled {
            return;
        }
        self.inner
            .decision_latency_ns_total
            .fetch_add(duration_ns, Ordering::Relaxed);
        self.inner.decision_latency_count.fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Credential metrics
    // ========================================================================

    /// Observe a credential injection success.
    pub fn observe_credential_injection_success(&self) {
        if !self.enabled {
            return;
        }
        self.inner
            .credential_injections_success
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Observe a credential injection failure.
    pub fn observe_credential_injection_failed(&self) {
        if !self.enabled {
            return;
        }
        self.inner
            .credential_injections_failed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Observe a credential lookup.
    pub fn observe_credential_lookup(&self, found: bool) {
        if !self.enabled {
            return;
        }
        self.inner.credential_lookups_total.fetch_add(1, Ordering::Relaxed);
        if !found {
            self.inner.credential_lookups_miss.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ========================================================================
    // Audit metrics
    // ========================================================================

    /// Observe an audit entry written.
    pub fn observe_audit_entry_written(&self) {
        if !self.enabled {
            return;
        }
        self.inner.audit_entries_written.fetch_add(1, Ordering::Relaxed);
    }

    /// Observe an audit chain verification.
    pub fn observe_audit_chain_verification(&self, success: bool) {
        if !self.enabled {
            return;
        }
        self.inner.audit_chain_verifications.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.inner.audit_chain_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ========================================================================
    // SAP / replay metrics
    // ========================================================================

    /// Observe a SAP verification.
    pub fn observe_sap_verification(&self, success: bool) {
        if !self.enabled {
            return;
        }
        self.inner.sap_verifications_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.inner.sap_verifications_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Observe a replay cache access.
    pub fn observe_replay_cache(&self, hit: bool) {
        if !self.enabled {
            return;
        }
        if hit {
            self.inner.replay_cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.replay_cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ========================================================================
    // Plugin audit metrics
    // ========================================================================

    /// Observe a plugin audit.
    pub fn observe_plugin_audit(&self, decision: &str) {
        if !self.enabled {
            return;
        }
        self.inner.plugin_audits_total.fetch_add(1, Ordering::Relaxed);
        match decision {
            "Pass" => self.inner.plugin_audits_pass.fetch_add(1, Ordering::Relaxed),
            "Reject" => self.inner.plugin_audits_reject.fetch_add(1, Ordering::Relaxed),
            "NeedHumanConfirm" => self.inner.plugin_audits_hitl.fetch_add(1, Ordering::Relaxed),
            _ => return,
        };
    }

    // ========================================================================
    // Error metrics
    // ========================================================================

    /// Observe an invalid PFP.
    pub fn observe_invalid_pfp(&self) {
        if !self.enabled {
            return;
        }
        self.inner.invalid_pfp.fetch_add(1, Ordering::Relaxed);
    }

    /// Observe an invalid SAP.
    pub fn observe_invalid_sap(&self) {
        if !self.enabled {
            return;
        }
        self.inner.invalid_sap.fetch_add(1, Ordering::Relaxed);
    }

    /// Observe a config error.
    pub fn observe_config_error(&self) {
        if !self.enabled {
            return;
        }
        self.inner.config_errors.fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Prometheus export
    // ========================================================================

    /// Export metrics in Prometheus text format.
    pub fn export_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096);

        // Help text and type declarations
        out.push_str("# HELP tuck_decisions_total Total number of security decisions by type.\n");
        out.push_str("# TYPE tuck_decisions_total counter\n");
        out.push_str(&format!(
            "tuck_decisions_total{{decision=\"pass\"}} {}\n",
            self.inner.decisions_pass.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_decisions_total{{decision=\"reject\"}} {}\n",
            self.inner.decisions_reject.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_decisions_total{{decision=\"hitl\"}} {}\n",
            self.inner.decisions_hitl.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_decisions_total{{decision=\"hard_override\"}} {}\n",
            self.inner.decisions_hard_override.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP tuck_risk_levels_total Total number of requests by risk level.\n");
        out.push_str("# TYPE tuck_risk_levels_total counter\n");
        out.push_str(&format!(
            "tuck_risk_levels_total{{risk=\"low\"}} {}\n",
            self.inner.risk_low.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_risk_levels_total{{risk=\"medium\"}} {}\n",
            self.inner.risk_medium.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_risk_levels_total{{risk=\"critical\"}} {}\n",
            self.inner.risk_critical.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_risk_levels_total{{risk=\"catastrophic\"}} {}\n",
            self.inner.risk_catastrophic.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP tuck_decision_latency_seconds Average decision latency in seconds.\n");
        out.push_str("# TYPE tuck_decision_latency_seconds gauge\n");
        let count = self.inner.decision_latency_count.load(Ordering::Relaxed);
        let total_ns = self.inner.decision_latency_ns_total.load(Ordering::Relaxed);
        let avg_latency_s = if count > 0 {
            total_ns as f64 / count as f64 / 1e9
        } else {
            0.0
        };
        out.push_str(&format!("tuck_decision_latency_seconds {:.9}\n", avg_latency_s));

        out.push_str("# HELP tuck_credential_injections_total Credential injection results.\n");
        out.push_str("# TYPE tuck_credential_injections_total counter\n");
        out.push_str(&format!(
            "tuck_credential_injections_total{{result=\"success\"}} {}\n",
            self.inner.credential_injections_success.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_credential_injections_total{{result=\"failed\"}} {}\n",
            self.inner.credential_injections_failed.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP tuck_credential_lookups_total Credential lookup results.\n");
        out.push_str("# TYPE tuck_credential_lookups_total counter\n");
        out.push_str(&format!(
            "tuck_credential_lookups_total{{result=\"hit\"}} {}\n",
            self.inner.credential_lookups_total.load(Ordering::Relaxed)
                - self.inner.credential_lookups_miss.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_credential_lookups_total{{result=\"miss\"}} {}\n",
            self.inner.credential_lookups_miss.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP tuck_audit_entries_total Total audit entries written.\n");
        out.push_str("# TYPE tuck_audit_entries_total counter\n");
        out.push_str(&format!(
            "tuck_audit_entries_total {}\n",
            self.inner.audit_entries_written.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP tuck_audit_chain_verifications_total Audit chain verification results.\n");
        out.push_str("# TYPE tuck_audit_chain_verifications_total counter\n");
        out.push_str(&format!(
            "tuck_audit_chain_verifications_total{{result=\"success\"}} {}\n",
            self.inner.audit_chain_verifications.load(Ordering::Relaxed)
                - self.inner.audit_chain_failures.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_audit_chain_verifications_total{{result=\"failure\"}} {}\n",
            self.inner.audit_chain_failures.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP tuck_sap_verifications_total SAP signature verification results.\n");
        out.push_str("# TYPE tuck_sap_verifications_total counter\n");
        out.push_str(&format!(
            "tuck_sap_verifications_total{{result=\"success\"}} {}\n",
            self.inner.sap_verifications_total.load(Ordering::Relaxed)
                - self.inner.sap_verifications_failed.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_sap_verifications_total{{result=\"failed\"}} {}\n",
            self.inner.sap_verifications_failed.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP tuck_replay_cache_total Replay cache access results.\n");
        out.push_str("# TYPE tuck_replay_cache_total counter\n");
        out.push_str(&format!(
            "tuck_replay_cache_total{{result=\"hit\"}} {}\n",
            self.inner.replay_cache_hits.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_replay_cache_total{{result=\"miss\"}} {}\n",
            self.inner.replay_cache_misses.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP tuck_plugin_audits_total Plugin audit results.\n");
        out.push_str("# TYPE tuck_plugin_audits_total counter\n");
        out.push_str(&format!(
            "tuck_plugin_audits_total{{decision=\"pass\"}} {}\n",
            self.inner.plugin_audits_pass.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_plugin_audits_total{{decision=\"reject\"}} {}\n",
            self.inner.plugin_audits_reject.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_plugin_audits_total{{decision=\"hitl\"}} {}\n",
            self.inner.plugin_audits_hitl.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP tuck_errors_total Total errors by type.\n");
        out.push_str("# TYPE tuck_errors_total counter\n");
        out.push_str(&format!(
            "tuck_errors_total{{type=\"invalid_pfp\"}} {}\n",
            self.inner.invalid_pfp.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_errors_total{{type=\"invalid_sap\"}} {}\n",
            self.inner.invalid_sap.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "tuck_errors_total{{type=\"config_error\"}} {}\n",
            self.inner.config_errors.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP tuck_uptime_seconds Uptime in seconds.\n");
        out.push_str("# TYPE tuck_uptime_seconds counter\n");
        out.push_str(&format!(
            "tuck_uptime_seconds {}\n",
            self.inner.start_time.elapsed().as_secs()
        ));

        out
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_enabled() {
        let metrics = Metrics::new();
        assert!(metrics.is_enabled());
    }

    #[test]
    fn test_metrics_disabled() {
        let metrics = Metrics::disabled();
        assert!(!metrics.is_enabled());
    }

    #[test]
    fn test_observe_decision() {
        let metrics = Metrics::new();
        metrics.observe_decision("Pass");
        metrics.observe_decision("Reject");
        metrics.observe_decision("NeedHumanConfirm");
        metrics.observe_decision("HardOverridePass");

        let output = metrics.export_prometheus();
        assert!(output.contains("tuck_decisions_total{decision=\"pass\"} 1"));
        assert!(output.contains("tuck_decisions_total{decision=\"reject\"} 1"));
        assert!(output.contains("tuck_decisions_total{decision=\"hitl\"} 1"));
        assert!(output.contains("tuck_decisions_total{decision=\"hard_override\"} 1"));
    }

    #[test]
    fn test_observe_risk_level() {
        let metrics = Metrics::new();
        metrics.observe_risk_level("Low");
        metrics.observe_risk_level("Critical");

        let output = metrics.export_prometheus();
        assert!(output.contains("tuck_risk_levels_total{risk=\"low\"} 1"));
        assert!(output.contains("tuck_risk_levels_total{risk=\"critical\"} 1"));
    }

    #[test]
    fn test_observe_decision_latency() {
        let metrics = Metrics::new();
        metrics.observe_decision_latency(1000); // 1 microsecond
        metrics.observe_decision_latency(2000); // 2 microseconds

        let output = metrics.export_prometheus();
        assert!(output.contains("tuck_decision_latency_seconds 0.000001500"));
    }

    #[test]
    fn test_credential_metrics() {
        let metrics = Metrics::new();
        metrics.observe_credential_injection_success();
        metrics.observe_credential_injection_failed();
        metrics.observe_credential_lookup(true);
        metrics.observe_credential_lookup(false);

        let output = metrics.export_prometheus();
        assert!(output.contains("tuck_credential_injections_total{result=\"success\"} 1"));
        assert!(output.contains("tuck_credential_injections_total{result=\"failed\"} 1"));
        assert!(output.contains("tuck_credential_lookups_total{result=\"hit\"} 1"));
        assert!(output.contains("tuck_credential_lookups_total{result=\"miss\"} 1"));
    }

    #[test]
    fn test_audit_metrics() {
        let metrics = Metrics::new();
        metrics.observe_audit_entry_written();
        metrics.observe_audit_chain_verification(true);
        metrics.observe_audit_chain_verification(false);

        let output = metrics.export_prometheus();
        assert!(output.contains("tuck_audit_entries_total 1"));
        assert!(output.contains("tuck_audit_chain_verifications_total{result=\"success\"} 1"));
        assert!(output.contains("tuck_audit_chain_verifications_total{result=\"failure\"} 1"));
    }

    #[test]
    fn test_sap_replay_metrics() {
        let metrics = Metrics::new();
        metrics.observe_sap_verification(true);
        metrics.observe_sap_verification(false);
        metrics.observe_replay_cache(true);
        metrics.observe_replay_cache(false);

        let output = metrics.export_prometheus();
        assert!(output.contains("tuck_sap_verifications_total{result=\"success\"} 1"));
        assert!(output.contains("tuck_sap_verifications_total{result=\"failed\"} 1"));
        assert!(output.contains("tuck_replay_cache_total{result=\"hit\"} 1"));
        assert!(output.contains("tuck_replay_cache_total{result=\"miss\"} 1"));
    }

    #[test]
    fn test_plugin_audit_metrics() {
        let metrics = Metrics::new();
        metrics.observe_plugin_audit("Pass");
        metrics.observe_plugin_audit("Reject");
        metrics.observe_plugin_audit("NeedHumanConfirm");

        let output = metrics.export_prometheus();
        assert!(output.contains("tuck_plugin_audits_total{decision=\"pass\"} 1"));
        assert!(output.contains("tuck_plugin_audits_total{decision=\"reject\"} 1"));
        assert!(output.contains("tuck_plugin_audits_total{decision=\"hitl\"} 1"));
    }

    #[test]
    fn test_error_metrics() {
        let metrics = Metrics::new();
        metrics.observe_invalid_pfp();
        metrics.observe_invalid_sap();
        metrics.observe_config_error();

        let output = metrics.export_prometheus();
        assert!(output.contains("tuck_errors_total{type=\"invalid_pfp\"} 1"));
        assert!(output.contains("tuck_errors_total{type=\"invalid_sap\"} 1"));
        assert!(output.contains("tuck_errors_total{type=\"config_error\"} 1"));
    }

    #[test]
    fn test_disabled_metrics_noop() {
        let metrics = Metrics::disabled();
        metrics.observe_decision("Pass");
        metrics.observe_risk_level("Low");

        let output = metrics.export_prometheus();
        // Even disabled, export works but shows zeros
        assert!(output.contains("tuck_decisions_total{decision=\"pass\"} 0"));
    }

    #[test]
    fn test_prometheus_format_contains_help_and_type() {
        let metrics = Metrics::new();
        let output = metrics.export_prometheus();
        assert!(output.contains("# HELP tuck_decisions_total"));
        assert!(output.contains("# TYPE tuck_decisions_total counter"));
        assert!(output.contains("# HELP tuck_uptime_seconds"));
    }

    #[test]
    fn test_metrics_clone_cheap() {
        let metrics = Metrics::new();
        metrics.observe_decision("Pass");
        let cloned = metrics.clone();
        cloned.observe_decision("Reject");

        // Both share the same inner Arc
        let output = metrics.export_prometheus();
        assert!(output.contains("tuck_decisions_total{decision=\"pass\"} 1"));
        assert!(output.contains("tuck_decisions_total{decision=\"reject\"} 1"));
    }
}
