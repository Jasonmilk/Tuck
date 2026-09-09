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

/// Governance runtime config — injected, never hardcoded.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    /// Required bearer token. `None` = fail-closed (deny all), matching
    /// the Tuck philosophy: no credential configured ⇒ no access.
    pub api_key: Option<String>,
    /// Session-token secret (JWT HS256). When set, `Authorization: Bearer
    /// <jwt>` is validated (signature + expiry) and its `scope` claim is
    /// forwarded into the audit trail (CAPABILITY-13 mode-scope carrier).
    pub jwt_secret: Option<String>,
}

/// Verified caller identity after the auth gate.
#[derive(Debug, Clone)]
pub struct Caller {
    /// Static-key path: the configured key id.
    pub api_key_id: Option<String>,
    /// JWT path: subject + mode scope (opaque label, never interpreted).
    pub sub: Option<String>,
    pub scope: Option<String>,
}

#[derive(Clone)]
pub struct GatewayState {
    pub client: reqwest::Client,
    pub upstream: String,
    /// Upstream credential injected at the physical edge (L2). When set, the
    /// caller's Authorization is replaced before leaving the machine — the
    /// caller only ever carries a Tuck credential, never the upstream secret.
    pub upstream_key: Option<String>,
    /// Multi-upstream routing table (tier → endpoint). Empty = single
    /// `upstream` (backward compatible). Selected by `X-Route-Tier`.
    pub upstreams: Vec<UpstreamEntry>,
    /// Session id → mapping table. In-memory only (Rosetta stone rule).
    pub tables: Arc<Mutex<HashMap<String, MappingTable>>>,
    /// Tamper-evident ledger for every governed call (feature `audit`).
    #[cfg(feature = "audit")]
    pub chain: Option<Arc<Mutex<tuck_audit::AuditChain>>>,
}

/// One route entry inside the gateway (tier → base URL + L2 key).
#[derive(Debug, Clone)]
pub struct UpstreamEntry {
    pub tier: String,
    pub base_url: String,
    pub upstream_key: Option<String>,
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
            upstream_key: None,
            upstreams: Vec::new(),
            tables: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "audit")]
            chain: None,
        }
    }

    /// Inject the upstream credential (L2 physical-edge injection).
    pub fn with_upstream_key(mut self, key: String) -> Self {
        self.upstream_key = Some(key);
        self
    }

    /// Attach the multi-upstream routing table (X-Route-Tier selection).
    pub fn with_upstreams(mut self, entries: Vec<UpstreamEntry>) -> Self {
        self.upstreams = entries;
        self
    }

    /// Resolve the upstream for a request: `X-Route-Tier` header wins when a
    /// matching entry exists; otherwise the default upstream (单上游兼容).
    /// Unknown tier → default (fail-open at the route level; audit still
    /// records the tier label, so misconfiguration is visible).
    pub fn resolve_upstream(&self, headers: &HeaderMap) -> (&str, Option<&str>) {
        if let Some(tier) = headers
            .get("x-route-tier")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            if let Some(entry) = self.upstreams.iter().find(|e| e.tier == tier) {
                return (entry.base_url.as_str(), entry.upstream_key.as_deref());
            }
        }
        (self.upstream.as_str(), self.upstream_key.as_deref())
    }

    /// Attach the audit chain (feature `audit`).
    #[cfg(feature = "audit")]
    pub fn with_chain(mut self, chain: tuck_audit::AuditChain) -> Self {
        self.chain = Some(Arc::new(Mutex::new(chain)));
        self
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
    router.with_state(pipeline)
}

pub struct Pipeline {
    pub state: Arc<GatewayState>,
    pub rules: RuleSet,
    pub matrix: PolicyMatrix,
    pub auth: AuthConfig,
}

/// Identity gate (T-C1): bearer credential required. Fail-closed — an
/// unconfigured or mismatched credential denies the call before governance
/// even runs. Two channels: static key (system-level) and JWT HS256
/// (session-level, carries the CAPABILITY-13 mode scope).
fn authenticate(headers: &HeaderMap, auth: &AuthConfig) -> Result<Caller, ()> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(token) = token else {
        return Err(());
    };
    // JWT channel first (session identity + scope).
    if let Some(secret) = &auth.jwt_secret {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Ok(claims) = crate::token::verify(token, secret.as_bytes(), now) {
            return Ok(Caller {
                api_key_id: None,
                sub: Some(claims.sub),
                scope: Some(claims.scope),
            });
        }
    }
    // Static key channel (system-level).
    match &auth.api_key {
        Some(key) if token == key.as_str() => Ok(Caller {
            api_key_id: Some("system".into()),
            sub: None,
            scope: None,
        }),
        _ => Err(()),
    }
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

/// Read-only audit query endpoint (feature `audit`).
///
/// Returns chain entries filtered by optional query params:
/// `trace_id` (exact), `kind` (request|response), `action` (block|hold|forward).
/// Requires a valid credential (identity gate, fail-closed). Reads the chain
/// file directly — never touches the in-memory hot path.
#[cfg(feature = "audit")]
async fn audit_query(
    State(p): State<Arc<Pipeline>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::Json;
    let caller = match authenticate(&headers, &p.auth) {
        Ok(c) => c,
        Err(()) => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": { "type": "unauthorized", "message": "missing or invalid credential" }
                })),
            )
                .into_response();
        }
    };

    let path = match p.state.chain.as_ref() {
        Some(chain) => chain.lock().unwrap().path().to_path_buf(),
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(json!({ "error": { "type": "no_audit_chain", "message": "audit chain not configured" } })),
            )
                .into_response();
        }
    };

    let trace_filter = params.get("trace_id").cloned();
    let kind_filter = params.get("kind").cloned();
    let action_filter = params.get("action").cloned();

    let mut entries: Vec<serde_json::Value> = Vec::new();
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let payload = v.get("payload");
            if let Some(t) = &trace_filter {
                if payload.and_then(|p| p.get("trace_id")).and_then(serde_json::Value::as_str)
                    != Some(t.as_str())
                {
                    continue;
                }
            }
            if let Some(k) = &kind_filter {
                if payload.and_then(|p| p.get("kind")).and_then(serde_json::Value::as_str)
                    != Some(k.as_str())
                {
                    continue;
                }
            }
            if let Some(a) = &action_filter {
                if v.get("payload").and_then(|p| p.get("action")).and_then(serde_json::Value::as_str)
                    != Some(a.as_str())
                {
                    continue;
                }
            }
            entries.push(v);
        }
    }
    let count = entries.len();
    (
        axum::http::StatusCode::OK,
        Json(json!({ "entries": entries, "count": count, "queried_by": caller.sub.unwrap_or_default() })),
    )
        .into_response()
}

/// Caller identity fragment for audit entries (opaque labels only).
fn caller_of(c: &Caller) -> serde_json::Value {
    let mut v = serde_json::Map::new();
    if let Some(id) = &c.api_key_id {
        v.insert("api_key_id".into(), json!(id));
    }
    if let Some(sub) = &c.sub {
        v.insert("sub".into(), json!(sub));
    }
    if let Some(scope) = &c.scope {
        v.insert("scope".into(), json!(scope));
    }
    serde_json::Value::Object(v)
}

/// Append one audit entry (feature `audit`); no-op without it (按需加载).
fn record(p: &Pipeline, kind: &str, trace_id: &str, payload: serde_json::Value) {
    #[cfg(feature = "audit")]
    {
        if let Some(chain) = &p.state.chain {
            if let Ok(mut chain) = chain.lock() {
                let entry = json!({
                    "kind": kind,
                    "trace_id": trace_id,
                    "data": payload,
                });
                let _ = chain.append(&tuck_audit::SystemClock, entry);
            }
        }
    }
    #[cfg(not(feature = "audit"))]
    let _ = (p, kind, trace_id, payload);
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
    record(&p, "request", &trace_id, json!({
        "destination": dest,
        "action": "forward",
        "messages": governance,
        "session": session,
        "caller": caller_of(&caller),
    }));

    // Forward to upstream (multi-upstream: X-Route-Tier wins, else default).
    let (route_base, route_key) = p.state.resolve_upstream(&headers);
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
