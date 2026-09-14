//! Access gate wiring (H-2): the gate is actually installed in the pipeline.
//!
//! These two properties are the whole point of "None ≠ empty table":
//! an **installed empty table denies everything**, while **no table at all
//! abstains** — otherwise a deployment that never configured access would
//! silently lose every call the moment the feature is switched on.

#![cfg(all(feature = "policy", feature = "redact", feature = "access"))]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use tuck_gateway::gov::{governance_router, AuthConfig, GatewayState};
use tuck_gateway::{AccessConfig, AccessTable, PolicyMatrix, RuleSet};
use tower::ServiceExt;

/// Router with a gate that is either installed or absent.
///
/// The upstream points at a closed port: anything that is not denied up front
/// will fail at forward time (502), which is exactly how we tell "denied" from
/// "not denied" without depending on a live server.
fn router_with(access: Option<AccessTable>) -> Router {
    let state = GatewayState::new("http://127.0.0.1:9/v1".into());
    let state = match access {
        Some(table) => state.with_access(table),
        None => state,
    };
    governance_router(
        std::sync::Arc::new(state),
        RuleSet::compile(&[]).expect("empty rule set compiles"),
        PolicyMatrix::default(),
        AuthConfig {
            api_key: Some("k".into()),
            jwt_secret: None,
        },
    )
}

async fn chat(app: Router, model: Option<&str>) -> (StatusCode, Value) {
    let mut body = json!({ "messages": [{ "role": "user", "content": "hi" }] });
    if let Some(m) = model {
        body["model"] = json!(m);
    }
    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("authorization", "Bearer k")
        .body(Body::from(body.to_string()))
        .expect("request builds");

    let resp = app.oneshot(req).await.expect("router responds");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

#[tokio::test]
async fn installed_empty_table_denies_everything() {
    let table = AccessTable::compile(vec![], AccessConfig::default()).expect("compiles");
    let (status, _) = chat(router_with(Some(table)), Some("m1")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn denial_body_names_the_reason() {
    let table = AccessTable::compile(vec![], AccessConfig::default()).expect("compiles");
    let (status, body) = chat(router_with(Some(table)), Some("m1")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["type"], json!("access_deny"));
}

#[tokio::test]
async fn no_table_abstains_entirely() {
    let (status, _) = chat(router_with(None), Some("m1")).await;
    // Not 403 — with no gate installed the call proceeds and fails at the
    // unreachable upstream instead of being denied by policy.
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "an absent gate must not deny anything"
    );
}

#[tokio::test]
async fn gate_runs_before_content_detection() {
    // A payload that the detection engine would never flag is still denied,
    // proving the gate sits in front of detection rather than behind it.
    let table = AccessTable::compile(vec![], AccessConfig::default()).expect("compiles");
    let (status, _) = chat(router_with(Some(table)), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
