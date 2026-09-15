//! Audit ledger writes.
//!
//! Split out of the governance pipeline (2026-09-15). Every governed call
//! lands here on its way to the tamper-evident chain. Without the `audit`
//! feature this is a no-op — 按需加载.
//!
//! The caller is recorded as **opaque labels only** (key id or subject); the
//! ledger never stores credentials.

use serde_json::json;

use crate::state::{Caller, Pipeline};

/// Caller identity fragment for audit entries (opaque labels only).
pub(crate) fn caller_of(c: &Caller) -> serde_json::Value {
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
pub(crate) fn record(p: &Pipeline, kind: &str, trace_id: &str, payload: serde_json::Value) {
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
