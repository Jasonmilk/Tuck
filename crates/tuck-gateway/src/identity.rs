//! Caller identity — who is speaking, and under which destination class.
//!
//! Split out of the governance pipeline (2026-09-15). The identity gate is
//! the first thing that runs and the only thing that can deny before any
//! payload is read, so it must be readable on its own.
//!
//! # Fail-closed
//!
//! No credential configured ⇒ no access. Two independent channels are
//! accepted (static key, and a session JWT carrying the CAPABILITY-13 scope);
//! neither is preferred by accident.

use axum::http::HeaderMap;

use crate::matrix::Destination;
use crate::state::AuthConfig;
use crate::state::Caller;

/// Identity gate (T-C1): bearer credential required. Fail-closed — an
/// unconfigured or mismatched credential denies the call before governance
/// even runs. Two channels: static key (system-level) and JWT HS256
/// (session-level, carries the CAPABILITY-13 mode scope).
pub(crate) fn authenticate(headers: &HeaderMap, auth: &AuthConfig) -> Result<Caller, ()> {
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

pub(crate) fn session_of(headers: &HeaderMap) -> String {
    headers
        .get("x-tuck-session")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(crate::state::DEFAULT_SESSION)
        .to_string()
}

pub(crate) fn destination_of(headers: &HeaderMap) -> Destination {
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
