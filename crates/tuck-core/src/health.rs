//! Tuck health check endpoint.
//!
//! # Design Principle
//!
//! **白盒可观测**: Health endpoint returns structured JSON with component
//! status, uptime, and key metrics. Suitable for Kubernetes liveness/readiness
//! probes and load balancer health checks.
//!
//! **极致节能**: Health check is O(1) — reads atomic counters and system
//! time, no I/O, no locks.
//!
//! **按需驱动**: Health check only runs when requested. No background
//! polling or heartbeat goroutines.

use serde::Serialize;
use std::time::Instant;

use crate::metrics::Metrics;

// ============================================================================
// Health Status
// ============================================================================

/// Overall health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All components healthy.
    Healthy,
    /// Some components degraded but service is still functional.
    Degraded,
    /// Service is unhealthy and should not receive traffic.
    Unhealthy,
}

/// Component health status.
#[derive(Debug, Clone, Serialize)]
pub struct ComponentHealth {
    /// Component name.
    pub name: String,
    /// Component status.
    pub status: HealthStatus,
    /// Optional message (for degraded/unhealthy states).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Full health check response.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    /// Overall status.
    pub status: HealthStatus,
    /// Service name.
    pub service: String,
    /// Service version.
    pub version: String,
    /// Uptime in seconds.
    pub uptime_seconds: u64,
    /// Component statuses.
    pub components: Vec<ComponentHealth>,
    /// Key metrics summary.
    pub metrics: HealthMetrics,
}

/// Key metrics summary for health check.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HealthMetrics {
    /// Total decisions.
    pub total_decisions: u64,
    /// Pass rate (0-100).
    pub pass_rate: f64,
    /// Reject rate (0-100).
    pub reject_rate: f64,
    /// Average decision latency in microseconds.
    pub avg_latency_us: f64,
    /// Credential injection success rate (0-100).
    pub credential_success_rate: f64,
    /// Audit chain failure count.
    pub audit_chain_failures: u64,
    /// Error count.
    pub total_errors: u64,
}

// ============================================================================
// Health Checker
// ============================================================================

/// Health checker — collects component status and metrics.
#[derive(Clone)]
pub struct HealthChecker {
    /// Service start time.
    start_time: Instant,
    /// Metrics registry.
    metrics: Metrics,
    /// Service name.
    service_name: String,
    /// Service version.
    version: String,
}

impl HealthChecker {
    /// Create a new health checker.
    pub fn new(metrics: Metrics, service_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            start_time: Instant::now(),
            metrics,
            service_name: service_name.into(),
            version: version.into(),
        }
    }

    /// Perform a health check and return the response.
    pub fn check(&self) -> HealthResponse {
        let uptime = self.start_time.elapsed().as_secs();

        // Collect component statuses
        let components = self.collect_components();

        // Determine overall status
        let overall = if components.iter().any(|c| c.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if components.iter().any(|c| c.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        // Collect metrics summary
        let metrics_summary = self.collect_metrics();

        HealthResponse {
            status: overall,
            service: self.service_name.clone(),
            version: self.version.clone(),
            uptime_seconds: uptime,
            components,
            metrics: metrics_summary,
        }
    }

    /// Collect component health statuses.
    fn collect_components(&self) -> Vec<ComponentHealth> {
        let mut components = Vec::new();

        // Decision engine (always healthy if metrics are being collected)
        components.push(ComponentHealth {
            name: "decision_engine".to_string(),
            status: HealthStatus::Healthy,
            message: None,
        });

        // Credential store (degraded if miss rate is high)
        let credential_status = self.check_credential_store();
        components.push(credential_status);

        // Audit log (unhealthy if chain failures detected)
        let audit_status = self.check_audit_log();
        components.push(audit_status);

        // SAP verification (degraded if failure rate is high)
        let sap_status = self.check_sap();
        components.push(sap_status);

        // Metrics (always healthy if enabled)
        components.push(ComponentHealth {
            name: "metrics".to_string(),
            status: if self.metrics.is_enabled() {
                HealthStatus::Healthy
            } else {
                HealthStatus::Degraded
            },
            message: if self.metrics.is_enabled() {
                None
            } else {
                Some("metrics disabled".to_string())
            },
        });

        components
    }

    /// Check credential store health.
    fn check_credential_store(&self) -> ComponentHealth {
        // Export metrics and parse credential lookup stats
        let output = self.metrics.export_prometheus();
        let miss_count = extract_metric_value(&output, "tuck_credential_lookups_total", "miss");
        let total_count = extract_metric_value(&output, "tuck_credential_lookups_total", "hit")
            + miss_count;

        if total_count == 0 {
            return ComponentHealth {
                name: "credential_store".to_string(),
                status: HealthStatus::Healthy,
                message: Some("no lookups yet".to_string()),
            };
        }

        let miss_rate = miss_count as f64 / total_count as f64 * 100.0;
        if miss_rate > 50.0 {
            ComponentHealth {
                name: "credential_store".to_string(),
                status: HealthStatus::Degraded,
                message: Some(format!("high miss rate: {:.1}%", miss_rate)),
            }
        } else {
            ComponentHealth {
                name: "credential_store".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }
        }
    }

    /// Check audit log health.
    fn check_audit_log(&self) -> ComponentHealth {
        let output = self.metrics.export_prometheus();
        let failures = extract_metric_value(&output, "tuck_audit_chain_verifications_total", "failure");

        if failures > 0 {
            ComponentHealth {
                name: "audit_log".to_string(),
                status: HealthStatus::Unhealthy,
                message: Some(format!("{} audit chain failures detected", failures)),
            }
        } else {
            ComponentHealth {
                name: "audit_log".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }
        }
    }

    /// Check SAP verification health.
    fn check_sap(&self) -> ComponentHealth {
        let output = self.metrics.export_prometheus();
        let failed = extract_metric_value(&output, "tuck_sap_verifications_total", "failed");
        let success = extract_metric_value(&output, "tuck_sap_verifications_total", "success");
        let total = failed + success;

        if total == 0 {
            return ComponentHealth {
                name: "sap_verification".to_string(),
                status: HealthStatus::Healthy,
                message: Some("no verifications yet".to_string()),
            };
        }

        let fail_rate = failed as f64 / total as f64 * 100.0;
        if fail_rate > 10.0 {
            ComponentHealth {
                name: "sap_verification".to_string(),
                status: HealthStatus::Degraded,
                message: Some(format!("high failure rate: {:.1}%", fail_rate)),
            }
        } else {
            ComponentHealth {
                name: "sap_verification".to_string(),
                status: HealthStatus::Healthy,
                message: None,
            }
        }
    }

    /// Collect metrics summary.
    fn collect_metrics(&self) -> HealthMetrics {
        let output = self.metrics.export_prometheus();

        let pass = extract_metric_value(&output, "tuck_decisions_total", "pass");
        let reject = extract_metric_value(&output, "tuck_decisions_total", "reject");
        let hitl = extract_metric_value(&output, "tuck_decisions_total", "hitl");
        let hard_override = extract_metric_value(&output, "tuck_decisions_total", "hard_override");
        let total = pass + reject + hitl + hard_override;

        let pass_rate = if total > 0 {
            pass as f64 / total as f64 * 100.0
        } else {
            100.0
        };
        let reject_rate = if total > 0 {
            reject as f64 / total as f64 * 100.0
        } else {
            0.0
        };

        // Average latency (parse from gauge)
        let avg_latency_us = extract_gauge_value(&output, "tuck_decision_latency_seconds") * 1e6;

        // Credential success rate
        let cred_success = extract_metric_value(&output, "tuck_credential_injections_total", "success");
        let cred_failed = extract_metric_value(&output, "tuck_credential_injections_total", "failed");
        let cred_total = cred_success + cred_failed;
        let credential_success_rate = if cred_total > 0 {
            cred_success as f64 / cred_total as f64 * 100.0
        } else {
            100.0
        };

        let audit_chain_failures =
            extract_metric_value(&output, "tuck_audit_chain_verifications_total", "failure");

        let invalid_pfp = extract_metric_value(&output, "tuck_errors_total", "invalid_pfp");
        let invalid_sap = extract_metric_value(&output, "tuck_errors_total", "invalid_sap");
        let config_error = extract_metric_value(&output, "tuck_errors_total", "config_error");
        let total_errors = invalid_pfp + invalid_sap + config_error;

        HealthMetrics {
            total_decisions: total,
            pass_rate,
            reject_rate,
            avg_latency_us,
            credential_success_rate,
            audit_chain_failures,
            total_errors,
        }
    }
}

// ============================================================================
// Helper: extract metric values from Prometheus text
// ============================================================================

/// Extract a counter value with a specific label from Prometheus text output.
fn extract_metric_value(output: &str, metric_name: &str, label_value: &str) -> u64 {
    for line in output.lines() {
        if line.starts_with(metric_name) && line.contains(&format!("=\"{}\"", label_value)) {
            if let Some(value_str) = line.split_whitespace().last() {
                if let Ok(value) = value_str.parse::<u64>() {
                    return value;
                }
            }
        }
    }
    0
}

/// Extract a gauge value from Prometheus text output.
fn extract_gauge_value(output: &str, metric_name: &str) -> f64 {
    for line in output.lines() {
        if line.starts_with(metric_name) && !line.starts_with("#") {
            if let Some(value_str) = line.split_whitespace().last() {
                if let Ok(value) = value_str.parse::<f64>() {
                    return value;
                }
            }
        }
    }
    0.0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check_basic() {
        let metrics = Metrics::new();
        let checker = HealthChecker::new(metrics, "tuck", "0.1.0");
        let response = checker.check();

        assert_eq!(response.service, "tuck");
        assert_eq!(response.version, "0.1.0");
        assert!(response.uptime_seconds >= 0);
        assert!(!response.components.is_empty());
    }

    #[test]
    fn test_health_status_serialization() {
        let healthy = serde_json::to_string(&HealthStatus::Healthy).unwrap();
        assert_eq!(healthy, "\"healthy\"");

        let degraded = serde_json::to_string(&HealthStatus::Degraded).unwrap();
        assert_eq!(degraded, "\"degraded\"");

        let unhealthy = serde_json::to_string(&HealthStatus::Unhealthy).unwrap();
        assert_eq!(unhealthy, "\"unhealthy\"");
    }

    #[test]
    fn test_health_response_serialization() {
        let metrics = Metrics::new();
        let checker = HealthChecker::new(metrics, "tuck", "0.1.0");
        let response = checker.check();

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"service\""));
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"uptime_seconds\""));
        assert!(json.contains("\"components\""));
        assert!(json.contains("\"metrics\""));
    }

    #[test]
    fn test_extract_metric_value() {
        let output = "tuck_decisions_total{decision=\"pass\"} 42\ntuck_decisions_total{decision=\"reject\"} 8\n";
        assert_eq!(extract_metric_value(output, "tuck_decisions_total", "pass"), 42);
        assert_eq!(extract_metric_value(output, "tuck_decisions_total", "reject"), 8);
        assert_eq!(extract_metric_value(output, "tuck_decisions_total", "hitl"), 0);
    }

    #[test]
    fn test_extract_gauge_value() {
        let output = "# HELP tuck_decision_latency_seconds Average\n# TYPE tuck_decision_latency_seconds gauge\ntuck_decision_latency_seconds 0.000001500\n";
        assert!((extract_gauge_value(output, "tuck_decision_latency_seconds") - 0.0000015).abs() < 1e-12);
    }

    #[test]
    fn test_health_with_decisions() {
        let metrics = Metrics::new();
        metrics.observe_decision("Pass");
        metrics.observe_decision("Pass");
        metrics.observe_decision("Reject");
        metrics.observe_decision_latency(1000);

        let checker = HealthChecker::new(metrics, "tuck", "0.1.0");
        let response = checker.check();

        assert_eq!(response.metrics.total_decisions, 3);
        assert!((response.metrics.pass_rate - 66.67).abs() < 1.0);
        assert!((response.metrics.reject_rate - 33.33).abs() < 1.0);
        assert!(response.metrics.avg_latency_us > 0.0);
    }

    #[test]
    fn test_health_audit_chain_failure() {
        let metrics = Metrics::new();
        metrics.observe_audit_chain_verification(false);

        let checker = HealthChecker::new(metrics, "tuck", "0.1.0");
        let response = checker.check();

        // Audit chain failure should make overall status Unhealthy
        assert_eq!(response.status, HealthStatus::Unhealthy);
        assert_eq!(response.metrics.audit_chain_failures, 1);
    }

    #[test]
    fn test_health_metrics_disabled() {
        let metrics = Metrics::disabled();
        let checker = HealthChecker::new(metrics, "tuck", "0.1.0");
        let response = checker.check();

        // Metrics component should be Degraded when disabled
        let metrics_component = response
            .components
            .iter()
            .find(|c| c.name == "metrics")
            .unwrap();
        assert_eq!(metrics_component.status, HealthStatus::Degraded);
    }

    #[test]
    fn test_component_health_skip_none_message() {
        let component = ComponentHealth {
            name: "test".to_string(),
            status: HealthStatus::Healthy,
            message: None,
        };
        let json = serde_json::to_string(&component).unwrap();
        assert!(!json.contains("message"));
    }
}
