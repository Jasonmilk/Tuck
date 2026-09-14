//! Access admission (H-1) — answers "where may this request go".
//!
//! Content governance (`policy` / `matrix`) answers a different question:
//! *what is in the payload*. Access admission runs **before** detection —
//! a destination that is not allowed never has its payload read
//! (`ADR-0005` D1).
//!
//! # List shape
//!
//! The table reuses CAPABILITY-13's `scope -> capability[]` mapping instead of
//! inventing a new list format (`ADR-0005` D2). The JWT `scope` claim is
//! already forwarded into the audit chain, so no new carrier is needed.
//!
//! # One table, two effects
//!
//! Allow and deny rules live in the **same** table with an `effect` field.
//! Two separate tables would declare one fact twice and leave priority to
//! convention; here priority is data: **deny wins** (`ADR-0005` D4).
//!
//! # Fail-closed
//!
//! - Nothing matches ⇒ `default_action`, whose default is `deny` (D5).
//!   An empty table therefore denies everything, matching the existing
//!   "no credential ⇒ no access" rule.
//! - A malformed table is rejected at **compile time**, not at request time —
//!   same shape as `RuleSet::compile` failing on an invalid regex (D6).
//!
//! # Determinism
//!
//! `admit` is a pure function: no clock, no network, no global state.
//! Same `(scope, capability, table)` ⇒ same verdict, byte for byte.

use serde::{Deserialize, Serialize};

use crate::capability::{required, Target};

/// Effect of one access rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

/// Admission behaviour — fully injected, zero hardcoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessConfig {
    /// Verdict when no rule matches. Default `deny` (D5).
    #[serde(default = "default_action")]
    pub default_action: Effect,
    /// Record the verdict, never enforce it. Lets a deployment observe
    /// before tightening (H-6) — without it, default-deny cuts off every
    /// unlisted caller on day one.
    #[serde(default)]
    pub observe_only: bool,
}

/// Default is deny: an unconfigured gate stays shut.
fn default_action() -> Effect {
    Effect::Deny
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            default_action: default_action(),
            observe_only: false,
        }
    }
}

/// One rule: a scope may (or may not) use a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRule {
    /// Stable id — this is what lands in the audit trail, so it must be
    /// unique and non-empty (D7: `why` has to be unambiguous).
    pub id: String,
    pub scope: String,
    pub capability: String,
    pub effect: Effect,
}

/// Compiled access table.
#[derive(Debug, Clone)]
pub struct AccessTable {
    rules: Vec<AccessRule>,
    config: AccessConfig,
}

/// Outcome of one admission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub effect: Effect,
    /// Rule that decided it. `None` ⇒ fell through to `default_action`.
    pub rule_id: Option<String>,
    /// Carried so the caller can log without enforcing (H-6).
    pub observe_only: bool,
}

impl Admission {
    /// Whether the request may proceed. In observe mode every verdict
    /// reports `true` — the decision is recorded, not applied.
    pub fn allowed(&self) -> bool {
        self.observe_only || self.effect == Effect::Allow
    }
}

impl AccessTable {
    /// Build a table. Every structural problem is a hard error: the gate
    /// must never be reachable in a half-configured state (D6).
    pub fn compile(rules: Vec<AccessRule>, config: AccessConfig) -> Result<Self, String> {
        let mut seen = std::collections::BTreeSet::new();
        for r in &rules {
            if r.id.trim().is_empty() {
                return Err("access rule: id must not be empty".into());
            }
            if r.scope.trim().is_empty() {
                return Err(format!("access rule {}: scope must not be empty", r.id));
            }
            if r.capability.trim().is_empty() {
                return Err(format!("access rule {}: capability must not be empty", r.id));
            }
            if !seen.insert(r.id.as_str()) {
                return Err(format!("access rule: duplicate id {:?} (audit `why` would be ambiguous)", r.id));
            }
        }
        Ok(Self { rules, config })
    }

    /// Decide whether `scope` may use `capability`.
    ///
    /// Matching is exact; deny wins over allow regardless of rule order.
    pub fn admit(&self, scope: &str, capability: &str) -> Admission {
        let mut allow: Option<&AccessRule> = None;
        for r in &self.rules {
            if r.scope != scope || r.capability != capability {
                continue;
            }
            if r.effect == Effect::Deny {
                return self.verdict(Some(r));
            }
            if allow.is_none() {
                allow = Some(r);
            }
        }
        self.verdict(allow)
    }

    fn verdict(&self, rule: Option<&AccessRule>) -> Admission {
        match rule {
            Some(r) => Admission {
                effect: r.effect,
                rule_id: Some(r.id.clone()),
                observe_only: self.config.observe_only,
            },
            None => Admission {
                effect: self.config.default_action,
                rule_id: None,
                observe_only: self.config.observe_only,
            },
        }
    }

    /// Admit one concrete request.
    ///
    /// Every capability the call needs must be allowed; the **first** denial
    /// wins and is returned with its rule id, so the audit trail can name the
    /// dimension that stopped the call.
    ///
    /// A caller without a scope cannot be authorised — there is nothing to
    /// look up — so it is denied outright instead of falling through to
    /// `default_action`, which a deployment may have relaxed.
    pub fn admit_request(&self, scope: Option<&str>, target: &Target) -> Admission {
        let scope = match scope {
            Some(s) if !s.trim().is_empty() => s,
            _ => {
                return Admission {
                    effect: Effect::Deny,
                    rule_id: None,
                    observe_only: self.config.observe_only,
                }
            }
        };
        let mut granted: Option<String> = None;
        for cap in required(target) {
            let a = self.admit(scope, &cap);
            if a.effect == Effect::Deny {
                return a;
            }
            if granted.is_none() {
                granted = a.rule_id;
            }
        }
        Admission {
            effect: Effect::Allow,
            rule_id: granted,
            observe_only: self.config.observe_only,
        }
    }

    /// Rules as configured — for tests and for config round-tripping.
    pub fn rules(&self) -> &[AccessRule] {
        &self.rules
    }
}
