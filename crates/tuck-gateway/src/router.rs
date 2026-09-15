//! Router assembly for the governance gateway.
//!
//! Split out of `gov.rs` (2026-09-15). This module bolts the endpoints onto an
//! axum Router and nothing else — 装配与流水线是两件事. The audit endpoints are
//! mounted only when the `audit` feature is on.

use std::sync::Arc;

use axum::Router;

#[cfg(feature = "audit")]
use crate::audit_api::{audit_query, audit_stats};
use crate::gov::governed_chat;
use crate::matrix::PolicyMatrix;
use crate::policy::RuleSet;
use crate::state::{AuthConfig, GatewayState, Pipeline};

/// Extend the gateway router with the full governance pipeline.
pub fn governance_router(
    state: Arc<GatewayState>,
    rules: RuleSet,
    matrix: PolicyMatrix,
    auth: AuthConfig,
) -> Router {
    let rules = Arc::new(tokio::sync::RwLock::new(rules));

    // Corpus hot reload is opt-in: only a configured path starts a watcher.
    if let Some(path) = state.rules_path.clone() {
        let interval = state.corpus_watch_interval_s;
        crate::reload::spawn_corpus_watchdog(path, Arc::clone(&rules), interval);
    }

    let pipeline = Arc::new(Pipeline {
        state,
        rules,
        matrix,
        auth,
    });
    let router = Router::new()
        .route("/v1/chat/completions", axum::routing::post(governed_chat));
    #[cfg(feature = "audit")]
    let router = router.route("/v1/audit", axum::routing::get(audit_query));
    #[cfg(feature = "audit")]
    let router = router.route("/v1/stats", axum::routing::get(audit_stats));
    router.with_state(pipeline)
}
