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

/// Capability vocabulary (feature `access`): CI-144 `domain:action[:qualifier]`.
#[cfg(feature = "access")]
pub mod capability;

/// Notification sinks for admission denials (feature `access`). No
/// implementation is built in — the deployment injects its own.
#[cfg(feature = "access")]
pub mod notify;
#[cfg(feature = "access")]
pub use notify::{Denial, Notify};

/// Access admission (feature `access`): scope → capability allow/deny gate.
/// Runs before detection — a destination that is not allowed is never read.
#[cfg(feature = "access")]
pub mod access;
#[cfg(feature = "access")]
pub use access::{AccessConfig, AccessRule, AccessTable, Admission, Effect};

/// Gateway state and injected configuration (features `policy` + `redact`).
#[cfg(all(feature = "policy", feature = "redact"))]
pub mod state;
#[cfg(all(feature = "policy", feature = "redact"))]
pub use state::{AuthConfig, Caller, GatewayState, Pipeline, UpstreamEntry};

/// Caller identity gate (features `policy` + `redact`).
#[cfg(all(feature = "policy", feature = "redact"))]
pub mod identity;

/// Audit ledger writes (features `policy` + `redact`).
#[cfg(all(feature = "policy", feature = "redact"))]
pub mod ledger;

/// Read-only audit endpoints (features `policy` + `redact` + `audit`).
#[cfg(all(feature = "policy", feature = "redact", feature = "audit"))]
pub mod audit_api;

/// Router assembly (features `policy` + `redact`).
#[cfg(all(feature = "policy", feature = "redact"))]
pub mod router;
#[cfg(all(feature = "policy", feature = "redact"))]
pub use router::governance_router;

/// Corpus hot reload (feature `policy`): swap detection rules without a restart.
#[cfg(feature = "policy")]
pub mod reload;

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

/// Semantic redaction (feature `redact`): entity → placeholder mapping.
#[cfg(feature = "redact")]
pub mod redact;
#[cfg(feature = "redact")]
pub use redact::{MappingTable, Replacement};

/// Full governance pipeline wiring (features `policy` + `redact`).
#[cfg(all(feature = "policy", feature = "redact"))]
pub mod gov;
#[cfg(all(feature = "policy", feature = "redact"))]

/// Session tokens (JWT HS256) — CAPABILITY-13 mode-scope carrier.
#[cfg(all(feature = "policy", feature = "redact"))]
pub mod token;
#[cfg(all(feature = "policy", feature = "redact"))]
pub use token::{Claims, TokenError, issue, verify};

/// Gateway configuration — no magic constants, everything injected.
///
/// **`Default` 是**刻意的**（2026-10-09, K16 M1b-1）**：本结构体将来要加可选字段
/// （`access` / `chain`，都是 `Option`），而调用方此前用**裸结构体字面量**构造它 ⇒
/// **加任何字段都会打破所有既有字面量**（与 proto 加 `system=5` 同形，第 27 条）。
/// ⇒ 先让 `Default` 存在，构造点一律写 `..Default::default()`，此后的字段扩张就不再是破坏性改动。
#[derive(Debug, Clone, Default)]
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
            /* M1a（2026-10-09）：把 anaphase 的「做」那道门接上。**先只给端点，不装配**。
             * 形状逐字对齐 anaphase 的既有契约（`src/security.rs:46` GateCheck /
             * `adapters/security_gate.rs:57` GateResponse）——**不新造接口**。
             * M1a 只回答一件事：**这个门在不在**（I7：没有装门不得看起来像门通过了）。 */
            .route("/v1/security/gate", post(security_gate))
            .with_state(state)
    }
}

/// anaphase 送来的门检请求（逐字对齐 `anaphase-helix/src/security.rs:46`）。
#[derive(serde::Deserialize)]
struct GateCheckIn {
    #[serde(default)] job_id: String,
    #[serde(default)] index: u32,
    #[serde(default)] tool: String,
    #[serde(default)] args_json: String,
    #[serde(default)] identity_labels: std::collections::BTreeMap<String, String>,
}

/// 回给 anaphase 的判定（逐字对齐 `anaphase-helix/src/adapters/security_gate.rs:57`）。
#[derive(serde::Serialize)]
struct GateResponseOut {
    decision: String,
    reason: String,
}

/* M1a：**只提供端点，不装配门**。
 *
 * 为什么先这样：M1（接门）与 M2（anaphase 装配）必须**分开** —— 一次只让一处变，
 * 坏了才知道是谁坏的（D8-PLAN §四）。而 M1a 本身要能回答一件事：**门在不在**。
 *
 * ★ 它遵守本仓自己的 I7（`pipeline/mod.rs:171`）：**"没有装门"必须明说，不得看起来像门通过了。**
 *   ⇒ 所以 `reason` 里写清 `gate=none`，而不是返回一个空的 reason 冒充"检查过了"。
 * ★ 观察态：本阶段一律 `pass`（**不改行为** —— 让 M2 的接线可以独立验证）。
 *   真正的判定（policy / access / catastrophic）在 M1b 接上；审计行也在 M1b 落（M1 验收②）。 */
async fn security_gate(Json(check): Json<GateCheckIn>) -> Response {
    let gate_present = false; /* M1b 会把这里换成 state 里的 access/chain 是否已装 */
    let why = if gate_present {
        "observe_mode; gate=installed (verdict 记录但暂不拦 —— M1b 接入策略与审计)"
    } else {
        "observe_mode; gate=none —— 未装配任何准入表（I7：没有装门不得看起来像门通过了）"
    };
    /* ★ 三个字段 M1a 就用了（而不是等到 M1b）——两个理由：
     * ① 它们是**审计行将来要写的东西**（`args_json` 的脱敏版 + `identity_labels`），
     *    现在先出现在 reason 里，M1b 接审计时就不会"忘了带上谁在调用"；
     * ② 不读它们会被 clippy 报 `never read` —— 而那条警告是**真信号**（M1a 还没判），
     *    **具名比静默强**：让它在输出里显形，而不是 `#[allow]` 掉。
     * ⚠️ `args_json` 只报**长度**，不报内容（脱敏的最小形态；真正的 redact 在 M1b 借 Tuck 的 redact 模块）。 */
    let labels = check.identity_labels.len();
    let body = GateResponseOut {
        decision: "pass".to_string(),
        reason: format!(
            "{why}; tool={} job={} index={} args_len={} labels={}",
            check.tool, check.job_id, check.index, check.args_json.len(), labels
        ),
    };
    (StatusCode::OK, Json(body)).into_response()
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
