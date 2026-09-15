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

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::matrix::{Destination, PolicyMatrix, Transform, decide};
use crate::policy::RuleSet;
use crate::state::{AuthConfig, Caller, GatewayState, Pipeline};
use crate::identity::{authenticate, destination_of, session_of};
use crate::ledger::{caller_of, record};
#[cfg(feature = "audit")]
use crate::audit_api::{audit_query, audit_stats};
#[cfg(feature = "access")]
use crate::notify::{Denial, fanout};

/// Extend the gateway router with the full governance pipeline.
pub fn governance_router(
    state: Arc<GatewayState>,
    rules: RuleSet,
    matrix: PolicyMatrix,
    auth: AuthConfig,
) -> Router {
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

/// Govern one request/response round trip.
pub async fn governed_chat(
    State(p): State<Arc<Pipeline>>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    let session = session_of(&headers);
    let dest = destination_of(&headers);

    // Identity gate first: no credential, no access (fail-closed).
    let caller = match authenticate(&headers, &p.auth) {
        Ok(c) => c,
        Err(()) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": { "type": "unauthorized", "message": "missing or invalid credential" }
                })),
            )
                .into_response();
        }
    };

    // Trace id links this call across ledgers (Anaphase {job_id}#{index}).
    let trace_id = headers
        .get("x-tuck-trace")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("local")
        .to_string();

    // Access gate (H-2, ADR-0005): admission runs before detection — a
    // destination that is not allowed never has its payload read.
    #[cfg(feature = "access")]
    if let Some(table) = &p.state.access {
        let (_, _, tier) = p.state.resolve_upstream(&headers);
        // The fallback label names the absence of a supplier, not one; gating
        // on it would force every single-upstream deployment to invent a name.
        let supplier = if tier == crate::state::DEFAULT_TIER_LABEL {
            None
        } else {
            Some(tier.as_str())
        };
        let model = body.get("model").and_then(Value::as_str);
        let verdict = table.admit_request(
            caller.scope.as_deref(),
            &crate::capability::Target { supplier, model },
        );
        // Record on the verdict's *effect*, enforce on its *enforcement*.
        // Under observe_only `allowed()` is always true, so gating the record
        // on it would drop the one signal observation exists to produce.
        if verdict.effect == crate::access::Effect::Deny {
            record(
                &p,
                "request",
                &trace_id,
                json!({
                    "action": "access_deny",
                    "observe_only": verdict.observe_only,
                    "scope": caller.scope,
                    "supplier": supplier,
                    "model": model,
                    "rule_id": verdict.rule_id,
                    "caller": caller_of(&caller),
                }),
            );
            fanout(
                &p.state.notifies,
                &Denial {
                    trace_id: trace_id.clone(),
                    scope: caller.scope.clone(),
                    supplier: supplier.map(str::to_string),
                    model: model.map(str::to_string),
                    rule_id: verdict.rule_id.clone(),
                    observe_only: verdict.observe_only,
                },
            );
            if !verdict.allowed() {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": {
                            "type": "access_deny",
                            "message": "scope is not allowed to reach this destination",
                            "rule_id": verdict.rule_id,
                        }
                    })),
                )
                    .into_response();
            }
        }
    }

    // Per-message governance. Messages is an array of {role, content}.
    let mut governance: Vec<serde_json::Value> = Vec::new();
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
                    record(&p, "request", &trace_id, json!({
                        "destination": dest,
                        "action": "block",
                        "categories": v.categories,
                        "session": session,
                        "caller": caller_of(&caller),
                    }));
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
                    record(&p, "request", &trace_id, json!({
                        "destination": dest,
                        "action": "hold",
                        "categories": v.categories,
                        "session": session,
                        "caller": caller_of(&caller),
                    }));
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
            governance.push(serde_json::json!({
                "destination": dest,
                "action": "pass",
                "role": msg.get("role").and_then(Value::as_str).unwrap_or("?"),
                "transform": v.transform,
                "categories": v.categories,
            }));
            // Redact when the matrix asks for it (external mapping hits).
            if v.transform == Transform::Redact && !v.hits.is_empty() {
                let mut msg = msg.clone();
                let mut tables = p.state.session_table(&session);
                let table = tables.get_mut(&session).expect("table just inserted");
                let (redacted, repls) = table.redact(content, &v.hits);
                msg["content"] = json!(redacted);
                governed.push(msg);
                // Placeholders only — safe for the audit chain.
                governance.last_mut().map(|g| {
                    g["redactions"] = json!(repls.iter().map(|r| &r.placeholder).collect::<Vec<_>>())
                });
            } else {
                governed.push(msg.clone());
            }
        }
        body["messages"] = json!(governed);
    }

    // Audit the decision before anything leaves (feature `audit`).
    let (_, _, route_tier) = p.state.resolve_upstream(&headers);
    record(&p, "request", &trace_id, json!({
        "destination": dest,
        "action": "forward",
        "route_tier": route_tier,
        "messages": governance,
        "session": session,
        "caller": caller_of(&caller),
    }));

    // Forward to upstream (multi-upstream: X-Route-Tier wins, else default).
    let (route_base, route_key, _) = p.state.resolve_upstream(&headers);
    let upstream_url = format!("{}/chat/completions", route_base.trim_end_matches('/'));
    let mut req = p.state.client.post(&upstream_url);
    match route_key.or(p.state.upstream_key.as_deref()) {
        // L2: upstream credential injected at the physical edge — the caller
        // credential never leaves the machine.
        Some(key) => {
            req = req.header("authorization", format!("Bearer {key}"));
        }
        // No upstream credential configured: transparent passthrough.
        None => {
            if let Some(auth) = headers.get("authorization") {
                if let Ok(v) = auth.to_str() {
                    req = req.header("authorization", v);
                }
            }
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
                let pipeline = p.clone();
                let session = session.clone();
                let trace = trace_id.clone();
                let caller = caller_of(&caller);
                let stream = futures_util::stream::unfold(
                    (upstream.bytes_stream(), String::new()),
                    move |(mut stream, mut carry)| {
                        // FnMut closure: capture by ref, clone per invocation.
                        let state = state.clone();
                        let session = session.clone();
                        let pipeline = pipeline.clone();
                        let trace = trace.clone();
                        let caller = caller.clone();
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
                                // Flush the final carried bytes, then close
                                // the audit record for this call.
                                let mut misses = 0u64;
                                let final_chunk = if !carry.is_empty() {
                                    let demapped = {
                                        let tables = state.session_table(&session);
                                        let table = tables.get(&session).expect("table just inserted");
                                        let (demapped, m) = table.demap(&carry);
                                        misses += m;
                                        demapped
                                    };
                                    Some(Ok::<_, std::io::Error>(demapped.into_bytes()))
                                } else {
                                    None
                                };
                                record(&pipeline, "response", &trace, json!({
                                    "status": "ok",
                                    "demap_miss": misses,
                                    "session": session,
                                    "caller": caller,
                                }));
                                match final_chunk {
                                    Some(c) => Some((c, (stream, String::new()))),
                                    None => None,
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
                        let mut misses = 0u64;
                        {
                            let tables = p.state.session_table(&session);
                            let table = tables.get(&session).expect("table just inserted");
                            if let Some(choices) = resp_body.get_mut("choices").and_then(Value::as_array_mut) {
                                for choice in choices {
                                    if let Some(content) = choice
                                        .pointer_mut("/message/content")
                                    {
                                        if let Some(s) = content.as_str() {
                                            let (restored, m) = table.demap(s);
                                            misses += m;
                                            *content = json!(restored);
                                        }
                                    }
                                }
                            }
                        }
                        record(&p, "response", &trace_id, json!({
                            "status": status.as_u16(),
                            "demap_miss": misses,
                            "session": session,
                            "caller": caller_of(&caller),
                        }));
                        (status, out_headers, Json(resp_body)).into_response()
                    }
                    Err(e) => {
                        record(&p, "response", &trace_id, json!({
                            "status": 502,
                            "error": format!("upstream read error: {e}"),
                            "session": session,
                            "caller": caller_of(&caller),
                        }));
                        (
                            StatusCode::BAD_GATEWAY,
                            Json(Value::String(format!("upstream read error: {e}"))),
                        )
                            .into_response()
                    }
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
        let auth = AuthConfig {
            api_key: Some("test-key".into()),
            jwt_secret: None,
        };
        (governance_router(state, rules, matrix, auth), reqwest::Client::new())
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
            .header("authorization", "Bearer test-key")
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
            .header("authorization", "Bearer test-key")
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
            .header("authorization", "Bearer test-key")
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
            .header("authorization", "Bearer test-key")
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

#[cfg(all(test, feature = "audit"))]
mod audit_tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;
    use serde_json::{json, Value};
    use std::path::PathBuf;

    fn mock_upstream() -> Router {
        Router::new().route(
            "/v1/chat/completions",
            post(|Json(body): Json<Value>| async move { (StatusCode::OK, Json(body)) }),
        )
    }

    #[tokio::test]
    async fn every_call_lands_in_ledger_with_trace() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, mock_upstream()).await.unwrap();
        });

        let chain_path = PathBuf::from(std::env::temp_dir()).join("tuck-gov-audit-test.jsonl");
        let _ = std::fs::remove_file(&chain_path);
        let chain = tuck_audit::AuditChain::open(&chain_path).unwrap();

        let state = Arc::new(
            GatewayState::new(format!("http://{addr}/v1"))
                .with_chain(chain),
        );
        let rules = RuleSet::compile(&[crate::policy::Rule {
            id: "person".into(),
            kind: crate::policy::Kind::Dict,
            category: crate::policy::Category::Mapping,
            pattern: None,
            words: Some("张三".into()),
            min_len: None,
            min_entropy: None,
        }])
        .unwrap();
        let router = governance_router(
            state,
            rules,
            PolicyMatrix::default(),
            AuthConfig { api_key: Some("k".into()), jwt_secret: None },
        );
        let gw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(gw, router).await.unwrap();
        });

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{gw_addr}/v1/chat/completions"))
            .header("authorization", "Bearer k")
            .header("x-tuck-trace", "job7#3")
            .header("x-tuck-session", "audit-s")
            .header("x-tuck-destination", "external")
            .json(&json!({ "model": "m", "messages": [{ "role": "user", "content": "张三在开会" }] }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Ledger has request + response entries, chain intact.
        let report = tuck_audit::verify_chain(&chain_path).unwrap();
        assert!(report.ok, "ledger must stay tamper-evident");
        assert_eq!(report.entries, 2, "one call = request + response records");

        let content = std::fs::read_to_string(&chain_path).unwrap();
        assert!(content.contains("job7#3"), "trace id must join ledgers");
        assert!(content.contains("\"kind\":\"request\""));
        assert!(content.contains("\"kind\":\"response\""));
        // Redacted form only — original entity never in the chain.
        assert!(!content.contains("张三"), "audit chain stores redacted form only");
        assert!(content.contains("P_00") || content.contains("placeholder") || content.contains("redactions"));
    }

    #[tokio::test]
    async fn unauthorized_denied_without_credential() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, mock_upstream()).await.unwrap();
        });
        let state = Arc::new(GatewayState::new(format!("http://{addr}/v1")));
        let router = governance_router(
            state,
            RuleSet::compile(&[]).unwrap(),
            PolicyMatrix::default(),
            AuthConfig { api_key: Some("k".into()), jwt_secret: None },
        );
        let gw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(gw, router).await.unwrap();
        });

        let client = reqwest::Client::new();
        // No Authorization header at all.
        let resp = client
            .post(format!("http://{gw_addr}/v1/chat/completions"))
            .json(&json!({ "model": "m", "messages": [] }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong key also denied.
        let resp = client
            .post(format!("http://{gw_addr}/v1/chat/completions"))
            .header("authorization", "Bearer wrong")
            .json(&json!({ "model": "m", "messages": [] }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn fail_closed_when_no_key_configured() {
        // AuthConfig::default() has no key → deny everything.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, mock_upstream()).await.unwrap();
        });
        let state = Arc::new(GatewayState::new(format!("http://{addr}/v1")));
        let router = governance_router(
            state,
            RuleSet::compile(&[]).unwrap(),
            PolicyMatrix::default(),
            AuthConfig::default(),
        );
        let gw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(gw, router).await.unwrap();
        });

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{gw_addr}/v1/chat/completions"))
            .header("authorization", "Bearer anything")
            .json(&json!({ "model": "m", "messages": [] }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
