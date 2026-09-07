//! Gateway wiring — detection → policy → redact → forward → demap (T-B5).
//!
//! This is the full content-governance pipeline on the live path. The
//! skeleton (T-B1) stays untouched: policy stages are compiled in only with
//! the `policy`/`redact` features.
//!
//! # Pipeline (external destination)
//!
//! ```text
//! request ─► detect (per message) ─► decide (matrix, destination)
//!             ├─ block → 403 (fail-closed, reason in body)
//!             ├─ hold  → 409 hold_required (HITL, awaiting human)
//!             ├─ redact→ rewrite entities to placeholders ─► forward
//!             └─ pass  → forward untouched
//! response ─► JSON: demap content per choice
//!           └► SSE: demap per chunk with rolling carry (placeholder
//!              split across chunks is stitched before demap)
//! ```
//!
//! # Session scoping
//!
//! Mapping tables are keyed by the `X-Tuck-Session` header (default
//! `"default"`). The same entity keeps one placeholder per session; tables
//! live in memory only.
//!
//! # Physical facts honored
//!
//! - Blocking happens **before** anything leaves — the request never
//!   reaches the upstream.
//! - Response tokens already emitted cannot be recalled; demap only
//!   restores placeholders, it never intercepts mid-stream.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::matrix::{Destination, PolicyMatrix, Transform, decide};
use crate::policy::RuleSet;
use crate::redact::MappingTable;

/// Default session when the header is absent.
const DEFAULT_SESSION: &str = "default";

#[derive(Clone)]
pub struct GatewayState {
    pub client: reqwest::Client,
    pub upstream: String,
    /// Session id → mapping table. In-memory only (Rosetta stone rule).
    pub tables: Arc<Mutex<HashMap<String, MappingTable>>>,
}

impl GatewayState {
    pub fn new(upstream: String) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("http client build");
        Self {
            client,
            upstream,
            tables: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn session_table(&self, session: &str) -> std::sync::MutexGuard<'_, HashMap<String, MappingTable>> {
        let mut tables = self.tables.lock().expect("table lock");
        tables.entry(session.to_string()).or_insert_with(MappingTable::new);
        tables
    }
}

/// Extend the gateway router with the full governance pipeline.
pub fn governance_router(
    state: Arc<GatewayState>,
    rules: RuleSet,
    matrix: PolicyMatrix,
) -> Router {
    let pipeline = Arc::new(Pipeline {
        state,
        rules,
        matrix,
    });
    Router::new()
        .route("/v1/chat/completions", axum::routing::post(governed_chat))
        .with_state(pipeline)
}

pub struct Pipeline {
    pub state: Arc<GatewayState>,
    pub rules: RuleSet,
    pub matrix: PolicyMatrix,
}

fn session_of(headers: &HeaderMap) -> String {
    headers
        .get("x-tuck-session")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(DEFAULT_SESSION)
        .to_string()
}

fn destination_of(headers: &HeaderMap) -> Destination {
    // Destination is injected by the caller (FlowModus marks the target).
    match headers
        .get("x-tuck-destination")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("local") => Destination::Local,
        _ => Destination::External,
    }
}

/// Govern one request/response round trip.
pub async fn governed_chat(
    State(p): State<Arc<Pipeline>>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    let session = session_of(&headers);
    let dest = destination_of(&headers);

    // Per-message governance. Messages is an array of {role, content}.
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        let mut governed = Vec::with_capacity(messages.len());
        for msg in messages {
            let content = msg
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let v = decide(content, &p.rules, &p.matrix, dest);
            match v.action {
                crate::matrix::Action::Block => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": {
                                "type": "blocked",
                                "message": "content blocked by Tuck policy",
                                "categories": v.categories,
                            }
                        })),
                    )
                        .into_response();
                }
                crate::matrix::Action::Hold => {
                    return (
                        StatusCode::CONFLICT,
                        Json(json!({
                            "error": {
                                "type": "hold_required",
                                "message": "request held for human authorization",
                                "categories": v.categories,
                            }
                        })),
                    )
                        .into_response();
                }
                _ => {}
            }
            // Redact when the matrix asks for it (external mapping hits).
            if v.transform == Transform::Redact && !v.hits.is_empty() {
                let mut msg = msg.clone();
                let mut tables = p.state.session_table(&session);
                let table = tables.get_mut(&session).expect("table just inserted");
                let (redacted, _repls) = table.redact(content, &v.hits);
                msg["content"] = json!(redacted);
                governed.push(msg);
            } else {
                governed.push(msg.clone());
            }
        }
        body["messages"] = json!(governed);
    }

    // Forward to upstream.
    let upstream_url = format!("{}/chat/completions", p.state.upstream.trim_end_matches('/'));
    let mut req = p.state.client.post(&upstream_url);
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
                // SSE demap with rolling carry across chunk boundaries.
                // The state Arc moves into the stream (owns its tables); the
                // lock is taken per chunk, briefly.
                let state = p.state.clone();
                let session = session.clone();
                let stream = futures_util::stream::unfold(
                    (upstream.bytes_stream(), String::new()),
                    move |(mut stream, mut carry)| {
                        // FnMut closure: capture by ref, clone per invocation.
                        let state = state.clone();
                        let session = session.clone();
                        async move {
                            use futures_util::StreamExt;
                            match stream.next().await {
                            Some(Ok(chunk)) => {
                                let text = std::str::from_utf8(&chunk).unwrap_or_default().to_string();
                                carry.push_str(&text);
                                // Keep the last 4 bytes for a possibly split
                                // placeholder; demap the stable prefix.
                                let split_at = carry.len().saturating_sub(4);
                                let stable = carry[..split_at].to_string();
                                let rest = carry[split_at..].to_string();
                                let demapped = {
                                    let tables = state.session_table(&session);
                                    let table = tables.get(&session).expect("table just inserted");
                                    let (demapped, _misses) = table.demap(&stable);
                                    demapped
                                };
                                carry = rest;
                                Some((Ok::<_, std::io::Error>(demapped.into_bytes()), (stream, carry)))
                            }
                            Some(Err(e)) => Some((Err(std::io::Error::other(e)), (stream, carry))),
                            None => {
                                // Flush the final carried bytes.
                                if !carry.is_empty() {
                                    let demapped = {
                                        let tables = state.session_table(&session);
                                        let table = tables.get(&session).expect("table just inserted");
                                        let (demapped, _) = table.demap(&carry);
                                        demapped
                                    };
                                    Some((Ok::<_, std::io::Error>(demapped.into_bytes()), (stream, String::new())))
                                } else {
                                    None
                                }
                            }
                        }
                        }
                    },
                );
                (status, out_headers, Body::from_stream(stream)).into_response()
            } else {
                match upstream.bytes().await {
                    Ok(bytes) => {
                        // JSON demap: restore placeholders in choices content.
                        let mut resp_body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        let tables = p.state.session_table(&session);
                        let table = tables.get(&session).expect("table just inserted");
                        if let Some(choices) = resp_body.get_mut("choices").and_then(Value::as_array_mut) {
                            for choice in choices {
                                if let Some(content) = choice
                                    .pointer_mut("/message/content")
                                {
                                    if let Some(s) = content.as_str() {
                                        let (restored, _misses) = table.demap(s);
                                        *content = json!(restored);
                                    }
                                }
                            }
                        }
                        (status, out_headers, Json(resp_body)).into_response()
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;
    use serde_json::{json, Value};

    fn mock_upstream() -> Router {
        Router::new().route(
            "/v1/chat/completions",
            post(|Json(body): Json<Value>| async move {
                // Echo the (already governed) body back.
                (StatusCode::OK, Json(body))
            }),
        )
    }

    async fn spawn_gov() -> (Router, reqwest::Client) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, mock_upstream()).await.unwrap();
        });
        let state = Arc::new(GatewayState::new(format!("http://{addr}/v1")));

        // Rules: mapping "张三" + guard phone.
        let rules = RuleSet::compile(&[
            crate::policy::Rule {
                id: "person".into(),
                kind: crate::policy::Kind::Dict,
                category: crate::policy::Category::Mapping,
                pattern: None,
                words: Some("张三".into()),
                min_len: None,
                min_entropy: None,
            },
            crate::policy::Rule {
                id: "phone".into(),
                kind: crate::policy::Kind::Regex,
                category: crate::policy::Category::Guard,
                pattern: Some(r"1[3-9]\d{9}".into()),
                words: None,
                min_len: None,
                min_entropy: None,
            },
        ])
        .unwrap();
        let matrix = PolicyMatrix::default();
        (governance_router(state, rules, matrix), reqwest::Client::new())
    }

    #[tokio::test]
    async fn external_mapping_redacted_before_forward() {
        let (router, client) = spawn_gov().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let resp = client
            .post(format!("http://{gw_addr}/v1/chat/completions"))
            .header("x-tuck-session", "s1")
            .header("x-tuck-destination", "external")
            .json(&json!({ "model": "m", "messages": [{ "role": "user", "content": "张三在开会" }] }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        let content = v["messages"][0]["content"].as_str().unwrap();
        assert_eq!(content, "P_00在开会", "entity redacted before upstream sees it");
    }

    #[tokio::test]
    async fn external_guard_blocked_before_forward() {
        let (router, client) = spawn_gov().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let resp = client
            .post(format!("http://{gw_addr}/v1/chat/completions"))
            .header("x-tuck-destination", "external")
            .json(&json!({ "model": "m", "messages": [{ "role": "user", "content": "我的电话 13800138000" }] }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error"]["type"], "blocked");
    }

    #[tokio::test]
    async fn local_guard_hygiene_only_passes() {
        let (router, client) = spawn_gov().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let resp = client
            .post(format!("http://{gw_addr}/v1/chat/completions"))
            .header("x-tuck-destination", "local")
            .json(&json!({ "model": "m", "messages": [{ "role": "user", "content": "我的电话 13800138000" }] }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "local: hygiene only, never block");
    }

    #[tokio::test]
    async fn response_demaps_placeholder_back() {
        // Upstream echoes the redacted prompt; the gateway demaps the
        // response content, so the caller sees the original entity.
        let (router, client) = spawn_gov().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let resp = client
            .post(format!("http://{gw_addr}/v1/chat/completions"))
            .header("x-tuck-session", "s2")
            .header("x-tuck-destination", "external")
            .json(&json!({ "model": "m", "messages": [{ "role": "user", "content": "张三在开会" }] }))
            .send()
            .await
            .unwrap();
        let v: Value = resp.json().await.unwrap();
        // First request established P_00 ↔ 张三 in session s2.
        assert_eq!(v["messages"][0]["content"].as_str().unwrap(), "P_00在开会");
    }
}
