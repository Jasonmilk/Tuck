//! `/v1/security/gate` 的判据（M1a 的第一个测试 —— 也是 K16 的第一道回归网）。
//!
//! 为什么它必须存在：`security_gate` 是"做"那道门在 Tuck 侧的入口，
//! 而**没有测试的入口等于没有入口**（本会话的 x 光教训：`pretooluse-gate.sh` 曾长期无测试）。
//!
//! 形状照 `tests/proxy.rs`（同一套 `oneshot` + `mock_upstream`，不新造测试框架）。
//! 判据只断言 M1a 能负责的东西：**端点存在 · 形状对得上 anaphase 的契约 · 且它【明说】门在不在**（I7）。
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tuck_gateway::{AccessConfig, AccessTable, Effect, Gateway, GatewayConfig};
use tower::ServiceExt;

fn mock_upstream() -> Router {
    Router::new().route(
        "/chat/completions",
        post(|Json(_b): Json<Value>| async { Json(json!({"ok": true})) }),
    )
}

async fn call(body: Value) -> (StatusCode, Value) {
    let gw = Gateway::new(GatewayConfig { upstream: "http://127.0.0.1:1/v1".to_string(), ..Default::default() });
    let app = gw.router();
    let _ = mock_upstream(); /* 保留同一套上游 mock 形状，便于 M1b 接审计后扩展 */
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/security/gate")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn gate_endpoint_exists_and_answers_the_agreed_shape() {
    let (status, v) = call(json!({
        "job_id": "run-test", "index": 0, "tool": "calc",
        "args_json": "{\"a\":1}", "identity_labels": {"scope": "local"}
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    /* 形状必须与 anaphase 期待的一致（decision / reason）——
     * 命名不同（例：`verdict`）会让对面解析失败，而那种失败会伪装成"门拒了"。 */
    assert!(v.get("decision").is_some(), "缺少 decision: {v}");
    assert!(v.get("reason").is_some(), "缺少 reason: {v}");
    /* M1a 一律 pass（观察态 = 不改行为）；真正的判定在 M1b。 */
    assert_eq!(v["decision"], "pass", "M1a 应当是观察态: {v}");
}

#[tokio::test]
async fn gate_reason_names_whether_a_gate_is_installed() {
    /* I7（本仓 `pipeline/mod.rs:171`）：**"没有装门"不得看起来像门通过了。**
     * M1a 未装配任何准入表 ⇒ reason 必须**明说** gate=none；返回 pass 的同时说清"没门"。 */
    let (_status, v) = call(json!({"job_id": "j", "index": 3, "tool": "t", "args_json": "{}"}))
        .await;
    let reason = v["reason"].as_str().unwrap_or("");
    assert!(reason.contains("gate=none"), "未装配时必须具名 gate=none，实得: {reason}");
    assert!(reason.contains("index=3"), "应当带上调用方的 index（M1b 审计要用）: {reason}");
}

/// M1b-2a：**装了准入表 ⇒ `reason` 必须具名（effect / rule_id / observe_only）**。
///
/// 这一例刻意构造成"观察态 + 默认拒绝"：**门会拒，但开着观察模式所以放行**。
/// 它同时演示人类那条纪律：**「只记不拦」≠「不记」** ——
/// `reason` 里必须看得到"它本来会拒、理由是什么"（否则观察模式就成了静默）。
#[tokio::test]
async fn installed_gate_names_its_verdict_even_in_observe_mode() {
    let table = AccessTable::compile(
        vec![],
        AccessConfig { default_action: Effect::Deny, observe_only: true },
    )
    .expect("compile");
    let gw = Gateway::new(GatewayConfig {
        upstream: "http://127.0.0.1:1/v1".to_string(),
        access: Some(table),
        ..Default::default()
    });
    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/security/gate")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"job_id":"j1","index":1,"tool":"calc","args_json":"{}"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::OK);
    let reason = v["reason"].as_str().unwrap_or("");
    /* 三件都要看得见：装了门 / 它的裁决 / 它是由哪条规则（或默认动作）得出的。 */
    assert!(reason.contains("gate=installed"), "必须说清门装上了: {reason}");
    assert!(reason.contains("effect=Deny"), "必须带判定（本例：默认拒绝）: {reason}");
    assert!(reason.contains("observe_only=true"), "必须带观察态标记: {reason}");
    /* 观察态 ⇒ 仍然 pass（不改行为）；但"本来会拒"已经在 reason 里具名。 */
    assert_eq!(v["decision"], "pass", "观察态应当放行: {v}");
}

/// M1b-2b：**M1 验收②** —— "每次判定在审计里留下一行"。
///
/// ★ 判据刻意**不只断言 reason 字符串**：那只能证明"它说它写了"。
///   这里在调用后**直接查账本本身**（`next_seq()` = 账本自己报的序号）——
///   与 Tuck 的原则一致：**呈现的东西必须来自承载者，而不是调用方的声明**。
#[cfg(feature = "audit")]
#[tokio::test]
async fn every_verdict_leaves_a_row_in_the_audit_chain() {
    use std::sync::{Arc, Mutex};
    let dir = std::env::temp_dir().join(format!("tuck-gate-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("chain.jsonl");
    let _ = std::fs::remove_file(&path);
    let chain = Arc::new(Mutex::new(tuck_audit::AuditChain::open(&path).expect("open")));
    let before = chain.lock().unwrap().next_seq();

    let gw = Gateway::new(GatewayConfig {
        upstream: "http://127.0.0.1:1/v1".to_string(),
        chain: Some(chain.clone()),
        ..Default::default()
    });
    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/security/gate")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"job_id":"j9","index":2,"tool":"calc","args_json":"{}"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let reason = v["reason"].as_str().unwrap_or("");
    assert!(reason.contains("audit=ok seq="), "reason 必须报出落账结果: {reason}");

    /* ① 账本自己报的序号必须前进一行（不是"我说我写了"，是**账本说它多了一行**）。 */
    let after = chain.lock().unwrap().next_seq();
    assert_eq!(after, before + 1, "账本序号应当前进 1（before={before} after={after}）");

    /* ② 那行必须真的在文件里，且带着判定的口径（不是一条空记录）。 */
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("security_gate"), "落账行必须带 source: {text}");
    assert!(text.contains("j9"), "落账行必须带 job_id（可归因）: {text}");
}
