//! Gateway runtime state and injected configuration.
//!
//! Split out of the governance pipeline (2026-09-15). Everything here is
//! **data**: what the gateway was configured with, and the in-memory side
//! tables the pipeline mutates. No request logic lives in this module — that
//! is the pipeline's job — so it can be read and reused without dragging in
//! the request path.
//!
//! # Fail-closed defaults
//!
//! Every credential-bearing field starts `None`, and `None` means *no access*:
//! an unconfigured gateway denies, it does not fall open.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;

use crate::redact::MappingTable;
#[cfg(feature = "access")]
use crate::access::AccessTable;
#[cfg(feature = "access")]
use crate::notify::Notify;

/// Default session when the header is absent.
pub(crate) const DEFAULT_SESSION: &str = "default";
/// Tier label used when no `X-Route-Tier` matched — the single-upstream
/// fallback. It names the *absence* of a supplier, not a supplier, so the
/// access gate must not treat it as one (single source for this string:
/// `resolve_upstream` and the gate both read it from here).
pub(crate) const DEFAULT_TIER_LABEL: &str = "default";

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
    /// Access admission table (feature `access`, ADR-0005).
    ///
    /// `None` = no gate installed, which is **not** the same as an empty
    /// table: an empty table denies everything, no table simply abstains.
    #[cfg(feature = "access")]
    pub access: Option<AccessTable>,
    /// Notification sinks for admission denials (feature `access`). Empty by
    /// default: no channel is built in (ADR-0005 D8).
    #[cfg(feature = "access")]
    pub notifies: Vec<Arc<dyn Notify>>,
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
            #[cfg(feature = "access")]
            access: None,
            #[cfg(feature = "access")]
            notifies: Vec::new(),
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
    /// Returns `(base_url, key, tier_label)` — the tier label is recorded in
    /// the audit trail ("free"/"openrouter"/…, "default" when no header).
    /// Unknown tier → default (fail-open at the route level; audit still
    /// records the tier label, so misconfiguration is visible).
    pub fn resolve_upstream(&self, headers: &HeaderMap) -> (&str, Option<&str>, String) {
        if let Some(tier) = headers
            .get("x-route-tier")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            if let Some(entry) = self.upstreams.iter().find(|e| e.tier == tier) {
                return (
                    entry.base_url.as_str(),
                    entry.upstream_key.as_deref(),
                    tier.to_string(),
                );
            }
        }
        (
            self.upstream.as_str(),
            self.upstream_key.as_deref(),
            DEFAULT_TIER_LABEL.to_string(),
        )
    }

    /// Attach the audit chain (feature `audit`).
    #[cfg(feature = "audit")]
    pub fn with_chain(mut self, chain: tuck_audit::AuditChain) -> Self {
        self.chain = Some(Arc::new(Mutex::new(chain)));
        self
    }

    /// Install the access gate (feature `access`). Until this is called the
    /// gate abstains entirely — deliberately different from installing an
    /// empty table, which denies every call.
    #[cfg(feature = "access")]
    pub fn with_access(mut self, table: AccessTable) -> Self {
        self.access = Some(table);
        self
    }

    /// Register a notification sink for admission denials (feature `access`).
    #[cfg(feature = "access")]
    pub fn with_notify(mut self, sink: Arc<dyn Notify>) -> Self {
        self.notifies.push(sink);
        self
    }

    pub(crate) fn session_table(&self, session: &str) -> std::sync::MutexGuard<'_, HashMap<String, MappingTable>> {
        let mut tables = self.tables.lock().expect("table lock");
        tables.entry(session.to_string()).or_insert_with(MappingTable::new);
        tables
    }
}
