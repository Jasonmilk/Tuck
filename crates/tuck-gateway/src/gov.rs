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
// Single source of truth for the placeholder shape: the SSE carry below must
// never re-spell `P_` or assume how wide a placeholder is.
use crate::redact::{PLACEHOLDER_MIN_DIGITS, PLACEHOLDER_PREFIX};
#[cfg(feature = "audit")]
use crate::audit_api::{audit_query, audit_stats};
#[cfg(feature = "access")]
use crate::notify::{Denial, fanout};

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
            let v = {
                let corpus = p.rules.read().await;
                decide(content, &corpus, &p.matrix, dest)
            };
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
                                // A placeholder may straddle this chunk
                                // boundary, so demap only the prefix that is
                                // known not to end inside one and retain the
                                // rest (see `stable_prefix_end`).
                                let split_at = stable_prefix_end(&carry);
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

/// Byte offset up to which the accumulated SSE `carry` is safe to demap and
/// emit right now; the bytes from there on wait for the next chunk.
///
/// A placeholder is `P_` followed by a body, so a token that is still open at
/// the end of the carry has to be carried **whole**. Emitting part of it is a
/// correctness failure twice over: the client can see half a placeholder, and
/// a prefix of a wider token (`P_10` of `P_100`) can resolve to the *wrong*
/// entity. The split therefore retreats to the start of the last
/// placeholder-shaped suffix — never to a fixed number of trailing bytes.
///
/// A fixed window is wrong in both directions. Too small, and it cannot hold
/// even the shortest token: a 4-byte window leaves the `P` of a 4-byte
/// `P_00` behind when the carry ends one byte past it. Too large is not a fix
/// either, because the window advances as bytes arrive and will slice through
/// a token that is already held (a 4-byte token straddles every window edge
/// that falls inside it).
///
/// The retreat is self-bounding for ordinary text: a suffix stays open only
/// while its body is one unbroken run of placeholder characters, and any
/// separator (space, punctuation, a non-body letter) terminates it, after
/// which the whole carry is emitted. Only an unbroken run of hex/alphanumeric
/// body characters — exactly the token the parser itself cannot decide yet —
/// keeps the tail growing.
///
/// Returned offsets are char boundaries: either `carry.len()` or the index of
/// an ASCII `P`.
fn stable_prefix_end(carry: &str) -> usize {
    // A placeholder opens at `P`; the last one that is still open wins,
    // because every token before it is decidable and safe to emit.
    for (i, c) in carry.char_indices().rev() {
        if c != 'P' {
            continue;
        }
        let suffix = &carry[i..];
        // Lone trailing `P`: its `_` may still arrive in the next chunk.
        if PLACEHOLDER_PREFIX.starts_with(suffix) {
            return i;
        }
        if let Some(body) = suffix.strip_prefix(PLACEHOLDER_PREFIX) {
            if open_placeholder_body(body) {
                return i;
            }
        }
        // `P` followed by anything else never opens a placeholder.
    }
    carry.len()
}

/// Is `body` (the characters after a `P_` in the carry) a prefix of a
/// placeholder body that is still growing, so its token can neither be
/// resolved nor safely split yet?
///
/// Mirrors [`parse_placeholder`](crate::redact) exactly: the body is the
/// maximal run of ASCII hex digits, and only when that run is shorter than the
/// width floor does the maximal alphanumeric paraphrase run apply.
fn open_placeholder_body(body: &str) -> bool {
    let hex = body.bytes().take_while(u8::is_ascii_hexdigit).count();
    if hex == body.len() {
        // One unbroken hex run: a later chunk may widen or terminate it.
        return true;
    }
    // The hex run is terminated by a non-hex character.
    if hex >= PLACEHOLDER_MIN_DIGITS {
        // Already wide enough to parse: the token is decidable now.
        return false;
    }
    // Narrower than the floor, so parsing falls back to the alphanumeric
    // paraphrase run — still open only while the body stays alphanumeric.
    body.bytes().all(|b| b.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::MappingTable;

    /// Replay a text through the exact carry → [`stable_prefix_end`] → demap
    /// pipeline the SSE path uses, one element of `chunks` at a time. Returns
    /// the running client-visible output after each chunk (the last entry is
    /// the whole response).
    fn replay_steps(table: &MappingTable, chunks: &[&str]) -> Vec<String> {
        let mut carry = String::new();
        let mut out = String::new();
        let mut steps = Vec::new();
        for chunk in chunks {
            carry.push_str(chunk);
            let at = stable_prefix_end(&carry);
            let (demapped, _) = table.demap(&carry[..at]);
            out.push_str(&demapped);
            carry = carry[at..].to_string();
            steps.push(out.clone());
        }
        let (demapped, _) = table.demap(&carry);
        out.push_str(&demapped);
        steps.push(out);
        steps
    }

    /// The two invariants that make the carry correct, checked after every
    /// chunk: nothing on the wire is out of order, and no partial placeholder
    /// was ever emitted.
    fn assert_wire_invariants(steps: &[String], expected: &str, ctx: &str) {
        for (k, step) in steps.iter().enumerate() {
            assert!(
                expected.starts_with(step.as_str()),
                "{ctx}: step {k} emitted bytes out of order: {step:?} is not a prefix of {expected:?}"
            );
            assert!(
                !step.contains(PLACEHOLDER_PREFIX),
                "{ctx}: step {k} put a partial placeholder on the wire: {step:?}"
            );
        }
        assert_eq!(steps.last().unwrap(), expected, "{ctx}: final output");
    }

    /// Every 2-way and every 3-way split of `text`, through the real carry.
    fn assert_all_splits(text: &str, expected: &str, table: &MappingTable) {
        for i in 0..=text.len() {
            let chunks = [&text[..i], &text[i..]];
            assert_wire_invariants(
                &replay_steps(table, &chunks),
                expected,
                &format!("2-way split at {i}"),
            );
        }
        for i in 0..=text.len() {
            for j in i..=text.len() {
                let chunks = [&text[..i], &text[i..j], &text[j..]];
                assert_wire_invariants(
                    &replay_steps(table, &chunks),
                    expected,
                    &format!("3-way split at {i},{j}"),
                );
            }
        }
    }

    /// The original report's 4-byte token, split at every position both as a
    /// 2-way and as a 3-way chunk boundary. Before the fix this mis-restored
    /// in 10 of 10 positions; the table drive makes 0/N observable.
    #[test]
    fn four_byte_placeholder_split_at_every_boundary() {
        let mut table = MappingTable::new();
        table.placeholder("SECRET"); // P_00 (four bytes, the familiar width)
        assert_all_splits("AXP_00YB", "AXSECRETYB", &table);
    }

    /// Same, for the wider `P_100`-class token a session past 256 entities
    /// emits — the case where the old fixed 4-byte carry was strictly worse.
    #[test]
    fn five_byte_placeholder_split_at_every_boundary() {
        let mut table = MappingTable::new();
        for i in 0..256u64 {
            table.placeholder(&format!("E{i}")); // P_00..P_ff
        }
        assert_eq!(table.placeholder("SECRET"), "P_100", "five-byte token");
        assert_all_splits("AXP_100YB", "AXSECRETYB", &table);
    }

    /// A wider token that merely *starts* like a narrower one must not resolve
    /// early: `P_10` arriving one chunk before the `0` that makes it `P_100`
    /// must never substitute `P_10`'s entity.
    #[test]
    fn prefix_of_wider_token_is_never_resolved_early() {
        let mut table = MappingTable::new();
        for i in 0..256u64 {
            table.placeholder(&format!("E{i}")); // P_00..P_ff; P_10 owns E16
        }
        assert_eq!(table.placeholder("TEN"), "P_100"); // five-byte token
        assert_eq!(table.demap("P_10").0, "E16");
        assert_eq!(table.demap("P_100").0, "TEN");

        let steps = replay_steps(&table, &["P_10", "0"]);
        assert_eq!(steps.last().unwrap(), "TEN", "must resolve the wide token");
        assert!(
            !steps[..steps.len() - 1].iter().any(|s| s.contains("E16")),
            "P_10's entity must never be emitted early: {steps:?}"
        );
    }

    /// A lone trailing `P` is held until the next chunk decides it.
    #[test]
    fn lone_trailing_p_is_held_then_decided() {
        let mut table = MappingTable::new();
        table.placeholder("SECRET");
        // `P` then `_` then `0` then `0`: the token only completes at the end.
        let steps = replay_steps(&table, &["AXP", "_", "0", "0", "YB"]);
        assert_wire_invariants(&steps, "AXSECRETYB", "byte-at-a-time token");
        assert_eq!(stable_prefix_end("AXP"), 2, "lone P held");
        assert_eq!(stable_prefix_end("AXP!"), 4, "P followed by ! is not a start");
    }

    /// Ordinary text that merely mentions `P_` must not stall: only a
    /// token-shaped suffix is held, so the carry is a word at most, never a
    /// function of the stream length.
    #[test]
    fn ordinary_text_with_prefix_does_not_grow_the_carry() {
        let mut table = MappingTable::new();
        table.placeholder("SECRET");

        // `P_` immediately followed by a separator can never become a
        // placeholder, so the carry never exceeds the transient `P_` itself.
        let punctuated = "note P_! and P_? and P_, ok. ".repeat(500);
        assert!(
            max_carry_held(&punctuated) <= 2,
            "nothing token-shaped may be held beyond the transient `P_`"
        );
        assert_eq!(replay_all(&table, &punctuated), punctuated);

        // Even when `P_` is followed by a word (an alphanumeric paraphrase
        // candidate), the held tail is one word — bounded, not growing.
        let wordy = "ask P_alice and P_bob then done. ".repeat(500);
        let held = max_carry_held(&wordy);
        assert!(held <= 16, "carry grew to {held} bytes, not bounded by a word");
        assert!(wordy.len() > 10_000, "input is long enough to matter");
    }

    /// Feed `text` one char at a time and return the largest number of bytes
    /// the carry ever retained.
    fn max_carry_held(text: &str) -> usize {
        let mut table = MappingTable::new();
        table.placeholder("SECRET");
        let mut carry = String::new();
        let mut max_held = 0usize;
        for ch in text.chars() {
            carry.push(ch);
            let at = stable_prefix_end(&carry);
            max_held = max_held.max(carry.len() - at);
            let _ = table.demap(&carry[..at]);
            carry = carry[at..].to_string();
        }
        let _ = table.demap(&carry);
        max_held
    }

    /// Full replay of `text` fed one char at a time.
    fn replay_all(table: &MappingTable, text: &str) -> String {
        let mut carry = String::new();
        let mut out = String::new();
        for ch in text.chars() {
            carry.push(ch);
            let at = stable_prefix_end(&carry);
            let (demapped, _) = table.demap(&carry[..at]);
            out.push_str(&demapped);
            carry = carry[at..].to_string();
        }
        let (demapped, _) = table.demap(&carry);
        out.push_str(&demapped);
        out
    }

    /// The split must never land outside a character: a multi-byte character
    /// next to a `P` is not a placeholder, and replaying it split at every char
    /// boundary must neither panic nor corrupt the output.
    #[test]
    fn multibyte_text_never_slices_outside_a_character() {
        let mut table = MappingTable::new();
        table.placeholder("SECRET"); // P_00
        let text = "前缀P中后缀P_00中P_😀";
        let expected = "前缀P中后缀SECRET中P_😀";

        let bounds: Vec<usize> = text
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(text.len()))
            .collect();
        for &b in &bounds {
            let steps = replay_steps(&table, &[&text[..b], &text[b..]]);
            // `expected` legitimately contains a literal `P_😀`, so check
            // ordering and the final value rather than "no `P_`".
            for (k, step) in steps.iter().enumerate() {
                assert!(
                    expected.starts_with(step.as_str()),
                    "split at {b}, step {k}: {step:?} is not a prefix of {expected:?}"
                );
            }
            assert_eq!(steps.last().unwrap(), expected, "split at {b}: final output");
        }
    }
}
