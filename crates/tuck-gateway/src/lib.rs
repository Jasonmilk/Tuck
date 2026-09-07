//! Content-governance gateway — the host for Tuck's core differentiation.
//!
//! Stage T-B1: OpenAI-compatible proxy skeleton. Every LLM call in the
//! ecosystem flows through this gateway; later stages attach detection,
//! policy, redaction and audit to this single door.
//!
//! # Route
//!
//! `POST /v1/chat/completions` — accepts an OpenAI-style JSON body, forwards
//! to the configured upstream, and streams back either JSON (non-stream) or
//! SSE chunks (stream) untouched. Headers are forwarded (authorization
//! transparency: Tuck is the exit, not the credential holder yet).
//!
//! # Design rules honored
//!
//! - **极致解耦**: pure proxy now; policy/redaction/audit attach later as
//!   composable stages, none of them compiled in unless enabled.
//! - **按需加载**: features `policy` / `redact` gate the content-governance
//!   stages; the skeleton itself is feature-free.
//! - **物理事实优先**: forwarding is byte-transparent — no buffering, no
//!   re-encoding, streaming passes chunks through as they arrive.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::Value;

/// Detection engine (feature `policy`): objective predicates over payloads.
#[cfg(feature = "policy")]
pub mod policy;
#[cfg(feature = "policy")]
pub use policy::{Category, Hit, Kind, Rule, RuleSet};

/// Policy matrix (feature `policy`): detection hits → actions, by destination.
#[cfg(feature = "policy")]
pub mod matrix;
#[cfg(feature = "policy")]
pub use matrix::{Action, Destination, PolicyMatrix, Transform, Verdict, decide};

/// Gateway configuration — no magic constants, everything injected.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Upstream OpenAI-compatible base URL (e.g. `http://127.0.0.1:8000/v1`).
    pub upstream: String,
}

#[derive(Clone)]
pub struct Gateway {
    client: reqwest::Client,
    config: GatewayConfig,
}

impl Gateway {
    pub fn new(config: GatewayConfig) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("http client build");
        Self { client, config }
    }

    /// Build the axum router. Callers mount it at any port (0 硬编码).
    pub fn router(self) -> Router {
        let state = Arc::new(self);
        Router::new()
            .route("/v1/chat/completions", post(chat_completions))
            .with_state(state)
    }
}

async fn chat_completions(
    State(gw): State<Arc<Gateway>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let upstream_url = format!("{}/chat/completions", gw.config.upstream.trim_end_matches('/'));

    // Forward with the caller's headers (authorization transparency).
    let mut req = gw.client.post(&upstream_url);
    if let Some(auth) = headers.get("authorization") {
        if let Ok(v) = auth.to_str() {
            req = req.header("authorization", v);
        }
    }
    req = req.header("content-type", "application/json");

    let is_stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);

    match req.json(&body).send().await {
        Ok(upstream) => {
            let status = upstream.status();
            let mut out_headers = HeaderMap::new();
            if let Some(ct) = upstream.headers().get("content-type") {
                out_headers.insert("content-type", ct.clone());
            }

            if is_stream {
                // SSE pass-through: stream chunks as they arrive (no buffer).
                let stream = upstream.bytes_stream();
                let body = Body::from_stream(stream);
                (status, out_headers, body).into_response()
            } else {
                match upstream.bytes().await {
                    Ok(bytes) => (status, out_headers, bytes).into_response(),
                    Err(e) => (
                        StatusCode::BAD_GATEWAY,
                        Json(Value::String(format!("upstream read error: {e}"))),
                    )
                        .into_response(),
                }
            }
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(Value::String(format!("upstream unreachable: {e}"))),
        )
            .into_response(),
    }
}
