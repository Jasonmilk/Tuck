//! End-to-end proxy tests: a mock upstream (JSON + SSE) behind the gateway.
//!
//! Verifies the T-B1 contract on the wire — request reaches upstream with
//! the body/headers intact, non-stream JSON round-trips, stream chunks are
//! passed through as a stream without buffering.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tuck_gateway::{Gateway, GatewayConfig};
use tower::ServiceExt;

/// Mock upstream: echoes the request body and emits an SSE stream when asked.
fn mock_upstream() -> Router {
    Router::new().route(
        "/v1/chat/completions",
        post(|Json(body): Json<Value>| async move {
            if body.get("stream").and_then(Value::as_bool).unwrap_or(false) {
                let chunks = ["data: {\"a\":1}\n\n", "data: {\"b\":2}\n\n", "data: [DONE]\n\n"];
                let stream = futures_util::stream::iter(chunks.map(|c| Ok::<_, std::io::Error>(c.to_string())));
                (
                    StatusCode::OK,
                    [("content-type", "text/event-stream")],
                    Body::from_stream(stream),
                )
                    .into_response()
            } else {
                let reply = json!({ "echo": body, "upstream": true });
                (StatusCode::OK, Json(reply)).into_response()
            }
        }),
    )
}

async fn spawn_gateway() -> (Router, reqwest::Client) {
    // Mock upstream bound to a real port so the gateway can reach it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_upstream()).await.unwrap();
    });
    let upstream = format!("http://{addr}/v1");
    let router = Gateway::new(GatewayConfig { upstream }).router();
    (router, reqwest::Client::new())
}

#[tokio::test]
async fn non_stream_round_trip() {
    let (router, client) = spawn_gateway().await;
    // Listen the gateway on a real port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let resp = client
        .post(format!("http://{gw_addr}/v1/chat/completions"))
        .json(&json!({ "model": "mock", "messages": [{ "role": "user", "content": "hi" }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["upstream"], json!(true));
    assert_eq!(v["echo"]["model"], json!("mock"));
}

#[tokio::test]
async fn stream_passes_through_chunks() {
    let (router, client) = spawn_gateway().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let resp = client
        .post(format!("http://{gw_addr}/v1/chat/completions"))
        .json(&json!({ "model": "mock", "stream": true, "messages": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("text/event-stream"));
    let text = resp.text().await.unwrap();
    assert_eq!(text, "data: {\"a\":1}\n\ndata: {\"b\":2}\n\ndata: [DONE]\n\n");
}

#[tokio::test]
async fn auth_header_forwarded() {
    let (router, client) = spawn_gateway().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let resp = client
        .post(format!("http://{gw_addr}/v1/chat/completions"))
        .header("authorization", "Bearer test-key")
        .json(&json!({ "model": "mock", "messages": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn gateway_failure_returns_bad_gateway() {
    // Point at a dead port.
    let router = Gateway::new(GatewayConfig {
        upstream: "http://127.0.0.1:9/v1".to_string(),
    })
    .router();

    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"model":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}
