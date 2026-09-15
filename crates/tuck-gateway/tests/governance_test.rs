//! Governance pipeline tests.
//!
//! Moved out of `gov.rs` (2026-09-15): the inline test module was 302 of the
//! file's 713 lines, and it — not `governed_chat` — was what pushed the file
//! past the 400-line decoupling limit. Integration test files are exempt, and
//! testing through the public API is a bonus: it proves the surface is
//! actually usable from outside the crate.

#![cfg(all(feature = "policy", feature = "redact"))]

#[cfg(test)]
mod governance {
    use std::sync::Arc;

    use tuck_gateway::policy::{Category, Kind, Rule};
    use tuck_gateway::{governance_router, AuthConfig, GatewayState, PolicyMatrix, RuleSet};
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Json;
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
            Rule {
                id: "person".into(),
                kind: Kind::Dict,
                category: Category::Mapping,
                pattern: None,
                words: Some("张三".into()),
                min_len: None,
                min_entropy: None,
            },
            Rule {
                id: "phone".into(),
                kind: Kind::Regex,
                category: Category::Guard,
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
mod audit_ledger {
    use std::sync::Arc;

    use tuck_gateway::policy::{Category, Kind, Rule};
    use tuck_gateway::{governance_router, AuthConfig, GatewayState, PolicyMatrix, RuleSet};
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Json;
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
        let rules = RuleSet::compile(&[Rule {
            id: "person".into(),
            kind: Kind::Dict,
            category: Category::Mapping,
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
