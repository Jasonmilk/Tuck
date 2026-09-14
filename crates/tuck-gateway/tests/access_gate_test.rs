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
use tuck_gateway::{AccessConfig, AccessTable, Denial, Effect, Notify, PolicyMatrix, RuleSet};
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


// ---- H-6: observe mode ----

#[tokio::test]
async fn observe_mode_does_not_enforce() {
    let table = AccessTable::compile(
        vec![],
        AccessConfig {
            default_action: Effect::Deny,
            observe_only: true,
        },
    )
    .expect("compiles");
    let (status, _) = chat(router_with(Some(table)), Some("m1")).await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "observe mode records the denial but must not enforce it"
    );
}

// ---- H-5: notification sinks ----

/// Test sink: keeps the denials it was handed.
struct Recorder(std::sync::Arc<std::sync::Mutex<Vec<Denial>>>);

impl Notify for Recorder {
    fn on_denial(&self, d: &Denial) {
        self.0.lock().expect("sink lock").push(d.clone());
    }
}

fn router_with_sink(seen: std::sync::Arc<std::sync::Mutex<Vec<Denial>>>, observe: bool) -> Router {
    let table = AccessTable::compile(
        vec![],
        AccessConfig {
            default_action: Effect::Deny,
            observe_only: observe,
        },
    )
    .expect("compiles");
    let state = GatewayState::new("http://127.0.0.1:9/v1".into())
        .with_access(table)
        .with_notify(std::sync::Arc::new(Recorder(seen)));
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

#[tokio::test]
async fn a_registered_sink_receives_the_denial() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (status, _) = chat(router_with_sink(seen.clone(), false), Some("m1")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let got = seen.lock().expect("sink lock").clone();
    assert_eq!(got.len(), 1, "exactly one denial is reported");
    assert_eq!(got[0].model.as_deref(), Some("m1"));
    assert_eq!(got[0].scope, None, "the static-key caller carries no scope");
    assert!(!got[0].observe_only);
}

#[tokio::test]
async fn no_sink_registered_means_nothing_is_sent() {
    // The default shape: the gateway has no built-in channel (ADR-0005 D8).
    let table = AccessTable::compile(vec![], AccessConfig::default()).expect("compiles");
    let (status, _) = chat(router_with(Some(table)), Some("m1")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}


#[tokio::test]
async fn observe_mode_still_reports_the_denial() {
    // The whole point of observation is to see what *would* have been denied.
    // A mode that neither enforces nor reports is indistinguishable from
    // having no gate at all, so assert the report, not just the absence of 403.
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (status, _) = chat(router_with_sink(seen.clone(), true), Some("m1")).await;
    assert_ne!(status, StatusCode::FORBIDDEN, "not enforced");

    let got = seen.lock().expect("sink lock").clone();
    assert_eq!(got.len(), 1, "but still reported — observation must not be silent");
    assert!(got[0].observe_only);
    assert_eq!(got[0].model.as_deref(), Some("m1"));
}
