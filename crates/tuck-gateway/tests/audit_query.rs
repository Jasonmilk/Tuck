//! Session-token (JWT) identity + read-only audit query endpoint.
//!
//! Covers: fail-closed with no credential, JWT access with scope forwarded
//! into the audit trail, and `GET /v1/audit?trace_id=` returning the
//! request/response pair for one governed call — the white-box read path.

#![cfg(all(feature = "policy", feature = "redact", feature = "audit"))]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tuck_audit::AuditChain;
use tuck_gateway::gov::{AuthConfig, GatewayState, governance_router};
use tuck_gateway::matrix::PolicyMatrix;
use tuck_gateway::policy::RuleSet;
use tuck_gateway::token::{Claims, issue};
use tower::ServiceExt;

fn mock_upstream() -> Router {
    Router::new().route(
        "/v1/chat/completions",
        post(|req: axum::extract::Request| async move {
            // Echo back the Authorization header the upstream actually saw —
            // this is what makes L2 credential injection physically verifiable.
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("none")
                .to_string();
            let body: Value = axum::body::to_bytes(req.into_body(), 1024 * 64)
                .await
                .map(|b| serde_json::from_slice(&b).unwrap_or(Value::Null))
                .unwrap_or(Value::Null);
            let reply = json!({ "echo": body, "upstream": true, "saw_auth": auth });
            (StatusCode::OK, Json(reply)).into_response()
        }),
    )
}

const SECRET: &str = "session-test-secret-0123456789";

/// Percent-encode a query value (trace ids contain `#`, a URL fragment
/// delimiter — must be escaped or it truncates the query).
fn urlencode(v: &str) -> String {
    v.replace('%', "%25").replace('#', "%23")
}

/// Per-call temp chain path (tests run in parallel; shared files collide).
fn chain_path() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("tuck-audit-query-{}-{n}.jsonl", std::process::id()))
}

fn partner_token() -> String {
    issue(
        SECRET.as_bytes(),
        &Claims {
            iss: "tuck".into(),
            sub: "driver-1".into(),
            scope: "partner".into(),
            iat: 1_700_000_000,
            exp: 1_900_000_000,
        },
    )
}

async fn spawn() -> (Router, reqwest::Client) {
    spawn_with_upstream_key(None).await
}

async fn spawn_with_upstream_key(upstream_key: Option<&str>) -> (Router, reqwest::Client) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_upstream()).await.unwrap();
    });
    let upstream = format!("http://{addr}/v1");
    let chain_path = chain_path();
    let chain = AuditChain::open(&chain_path).unwrap();
    let mut state = GatewayState::new(upstream);
    if let Some(key) = upstream_key {
        state = state.with_upstream_key(key.to_string());
    }
    let state = state.with_chain(chain);
    let auth = AuthConfig {
        api_key: Some("static-key".into()),
        jwt_secret: Some(SECRET.into()),
    };
    let rules = RuleSet::compile(&[]).unwrap();
    let router = governance_router(std::sync::Arc::new(state), rules, PolicyMatrix::default(), auth);
    (router, reqwest::Client::new())
}

async fn governed(router: &Router, token: &str) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .header("x-tuck-trace", "job#0")
                .body(Body::from(
                    json!({ "model": "m", "messages": [{"role": "user", "content": "hi"}] })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
        .await
        .map(|b| serde_json::from_slice(&b).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    (status, body)
}

async fn audit_query(router: &Router, token: &str, trace: &str) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/audit?trace_id={}", urlencode(trace)))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
        .await
        .map(|b| serde_json::from_str(&String::from_utf8_lossy(&b)).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn jwt_scope_lands_in_audit_and_query_returns_pair() {
    let (router, _client) = spawn().await;
    let token = partner_token();

    // 1. No credential → 401 (fail-closed).
    let (status, _) = governed(&router, "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 2. JWT access → governed call forwards.
    let (status, body) = governed(&router, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["upstream"], true);

    // 3. trace id = job#0 per call; read the chain tail via query.
    // The ledger is deterministic: first call → trace "job#0".
    let (status, result) = audit_query(&router, &token, "job#0").await;
    assert_eq!(status, StatusCode::OK);
    let entries = result["entries"].as_array().expect("entries array");
    assert_eq!(result["count"], 2, "request + response pair");
    assert_eq!(entries[0]["payload"]["kind"], "request");
    assert_eq!(entries[1]["payload"]["kind"], "response");
    assert_eq!(entries[0]["payload"]["data"]["caller"]["sub"], "driver-1");
    assert_eq!(entries[0]["payload"]["data"]["caller"]["scope"], "partner");
}

#[tokio::test]
async fn audit_query_requires_credential() {
    let (router, _client) = spawn().await;
    let (status, _) = audit_query(&router, "", "job#0").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn upstream_key_replaces_caller_credential_at_the_edge() {
    // The caller only ever carries a Tuck credential; the upstream secret
    // is injected by Tuck (L2). The upstream must never see the caller key.
    let (router, _client) = spawn_with_upstream_key(Some("sk-upstream-secret")).await;
    let (status, body) = governed(&router, "static-key").await;
    assert_eq!(status, StatusCode::OK);
    let seen = body["saw_auth"].as_str().unwrap_or("");
    assert!(
        !seen.contains("static-key"),
        "caller credential leaked upstream: {seen}"
    );
    assert_eq!(seen, "Bearer sk-upstream-secret");
}

#[tokio::test]
async fn static_key_still_works_system_level() {
    let (router, _client) = spawn().await;
    let (status, _) = governed(&router, "static-key").await;
    assert_eq!(status, StatusCode::OK);
}
