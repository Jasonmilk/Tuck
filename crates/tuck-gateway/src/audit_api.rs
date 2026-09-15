//! Read-only audit endpoints.
//!
//! Split out of the governance pipeline (2026-09-15). These answer questions
//! *about* the ledger — they never touch the request path. They read the
//! chain file directly and are gated by the same identity check, so they are
//! fail-closed in exactly the same way as the pipeline.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde_json::{json, Value};

use crate::identity::authenticate;
use crate::ledger::caller_of;
use crate::state::{AuthConfig, Pipeline};

/// Read-only audit query endpoint (feature `audit`).
///
/// Returns chain entries filtered by optional query params:
/// `trace_id` (exact), `kind` (request|response), `action` (block|hold|forward).
/// Requires a valid credential (identity gate, fail-closed). Reads the chain
/// file directly — never touches the in-memory hot path.
#[cfg(feature = "audit")]
pub(crate) async fn audit_query(
    State(p): State<Arc<Pipeline>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::Json;
    let caller = match authenticate(&headers, &p.auth) {
        Ok(c) => c,
        Err(()) => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": { "type": "unauthorized", "message": "missing or invalid credential" }
                })),
            )
                .into_response();
        }
    };

    let path = match p.state.chain.as_ref() {
        Some(chain) => chain.lock().unwrap().path().to_path_buf(),
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(json!({ "error": { "type": "no_audit_chain", "message": "audit chain not configured" } })),
            )
                .into_response();
        }
    };

    let trace_filter = params.get("trace_id").cloned();
    let kind_filter = params.get("kind").cloned();
    let action_filter = params.get("action").cloned();

    let mut entries: Vec<serde_json::Value> = Vec::new();
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let payload = v.get("payload");
            if let Some(t) = &trace_filter {
                if payload.and_then(|p| p.get("trace_id")).and_then(serde_json::Value::as_str)
                    != Some(t.as_str())
                {
                    continue;
                }
            }
            if let Some(k) = &kind_filter {
                if payload.and_then(|p| p.get("kind")).and_then(serde_json::Value::as_str)
                    != Some(k.as_str())
                {
                    continue;
                }
            }
            if let Some(a) = &action_filter {
                if v.get("payload").and_then(|p| p.get("action")).and_then(serde_json::Value::as_str)
                    != Some(a.as_str())
                {
                    continue;
                }
            }
            entries.push(v);
        }
    }
    let count = entries.len();
    (
        axum::http::StatusCode::OK,
        Json(json!({ "entries": entries, "count": count, "queried_by": caller.sub.unwrap_or_default() })),
    )
        .into_response()
}

/// Read-only audit stats endpoint (feature `audit`).
///
/// Aggregates the chain for the cockpit's 检定台: destination counts,
/// kind/action buckets, last N events. Same identity gate, same
/// read-the-file path — never touches the in-memory hot path.
#[cfg(feature = "audit")]
pub(crate) async fn audit_stats(
    State(p): State<Arc<Pipeline>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::Json;
    let caller = match authenticate(&headers, &p.auth) {
        Ok(c) => c,
        Err(()) => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": { "type": "unauthorized", "message": "missing or invalid credential" }
                })),
            )
                .into_response();
        }
    };

    let path = match p.state.chain.as_ref() {
        Some(chain) => chain.lock().unwrap().path().to_path_buf(),
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(json!({ "error": { "type": "no_audit_chain", "message": "audit chain not configured" } })),
            )
                .into_response();
        }
    };

    let mut dest: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut tiers: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut kinds: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut actions: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut total: u64 = 0;
    let mut last: Vec<serde_json::Value> = Vec::new();

    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines().rev() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            total += 1;
            let payload = v.get("payload");
            let kind = payload
                .and_then(|p| p.get("kind"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?")
                .to_string();
            *kinds.entry(kind.clone()).or_insert(0) += 1;
            if let Some(data) = payload.and_then(|p| p.get("data")) {
                if let Some(d) = data.get("destination").and_then(serde_json::Value::as_str) {
                    *dest.entry(d.to_string()).or_insert(0) += 1;
                }
                if let Some(t) = data.get("route_tier").and_then(serde_json::Value::as_str) {
                    *tiers.entry(t.to_string()).or_insert(0) += 1;
                } else if kind == "request" {
                    // 历史记录（tier 字段加入前）归入 default——审计链
                    // append-only 不回溯，统计层兼容旧格式。
                    *tiers.entry("default".to_string()).or_insert(0) += 1;
                }
                if let Some(a) = data.get("action").and_then(serde_json::Value::as_str) {
                    *actions.entry(a.to_string()).or_insert(0) += 1;
                }
            }
            if kind == "request" && last.len() < 12 {
                // 只摘路由可见字段，不泄 prompt 正文（秘密卫生）
                let mut slim = serde_json::Map::new();
                slim.insert("seq".into(), v.get("seq").cloned().unwrap_or(json!(null)));
                slim.insert("ts".into(), v.get("ts").cloned().unwrap_or(json!(null)));
                if let Some(data) = payload.and_then(|p| p.get("data")) {
                    if let Some(d) = data.get("destination") {
                        slim.insert("destination".into(), d.clone());
                    }
                    if let Some(t) = data.get("route_tier") {
                        slim.insert("route_tier".into(), t.clone());
                    }
                    if let Some(a) = data.get("action") {
                        slim.insert("action".into(), a.clone());
                    }
                    if let Some(s) = data.get("status") {
                        slim.insert("status".into(), s.clone());
                    }
                }
                last.push(json!(slim));
            }
        }
    }

    (
        axum::http::StatusCode::OK,
        Json(json!({
            "total": total,
            "kinds": kinds,
            "destinations": dest,
            "tiers": tiers,
            "actions": actions,
            "last_requests": last,
            "queried_by": caller.sub.unwrap_or_default(),
        })),
    )
        .into_response()
}
