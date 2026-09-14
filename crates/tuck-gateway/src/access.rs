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

    /// Rules as configured — for tests and for config round-tripping.
    pub fn rules(&self) -> &[AccessRule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, scope: &str, capability: &str, effect: Effect) -> AccessRule {
        AccessRule {
            id: id.into(),
            scope: scope.into(),
            capability: capability.into(),
            effect,
        }
    }

    fn table(rules: Vec<AccessRule>, config: AccessConfig) -> AccessTable {
        AccessTable::compile(rules, config).expect("table must compile")
    }

    #[test]
    fn explicit_allow_admits() {
        let t = table(
            vec![rule("r1", "external_network", "llm:invoke:agnes", Effect::Allow)],
            AccessConfig::default(),
        );
        let a = t.admit("external_network", "llm:invoke:agnes");
        assert_eq!(a.effect, Effect::Allow);
        assert_eq!(a.rule_id.as_deref(), Some("r1"));
        assert!(a.allowed());
    }

    #[test]
    fn explicit_deny_rejects() {
        let t = table(
            vec![rule("r1", "external_network", "llm:invoke:agnes", Effect::Deny)],
            AccessConfig::default(),
        );
        let a = t.admit("external_network", "llm:invoke:agnes");
        assert_eq!(a.effect, Effect::Deny);
        assert!(!a.allowed());
    }

    #[test]
    fn deny_wins_regardless_of_order() {
        let allow_first = table(
            vec![
                rule("allow", "s", "c", Effect::Allow),
                rule("deny", "s", "c", Effect::Deny),
            ],
            AccessConfig::default(),
        );
        let deny_first = table(
            vec![
                rule("deny", "s", "c", Effect::Deny),
                rule("allow", "s", "c", Effect::Allow),
            ],
            AccessConfig::default(),
        );
        let a = allow_first.admit("s", "c");
        let b = deny_first.admit("s", "c");
        assert_eq!(a.effect, Effect::Deny);
        assert_eq!(b.effect, Effect::Deny);
        assert_eq!(a.rule_id.as_deref(), Some("deny"));
        assert_eq!(b.rule_id.as_deref(), Some("deny"));
        assert_eq!(a, b, "rule order must not change the verdict");
    }

    #[test]
    fn unmatched_falls_through_to_default_deny() {
        let t = table(
            vec![rule("r1", "s", "c", Effect::Allow)],
            AccessConfig::default(),
        );
        let a = t.admit("s", "other");
        assert_eq!(a.effect, Effect::Deny);
        assert_eq!(a.rule_id, None, "falling through must be distinguishable from a rule hit");
        assert!(!a.allowed());
    }

    #[test]
    fn empty_table_denies_everything() {
        let t = table(vec![], AccessConfig::default());
        assert_eq!(t.admit("any", "llm:egress").effect, Effect::Deny);
    }

    #[test]
    fn default_action_is_configurable_to_allow() {
        let t = table(
            vec![],
            AccessConfig { default_action: Effect::Allow, observe_only: false },
        );
        assert_eq!(t.admit("any", "llm:egress").effect, Effect::Allow);
    }

    #[test]
    fn scope_isolation_same_capability_different_scope() {
        let t = table(
            vec![rule("r1", "scope_a", "llm:egress", Effect::Allow)],
            AccessConfig::default(),
        );
        assert_eq!(t.admit("scope_a", "llm:egress").effect, Effect::Allow);
        assert_eq!(t.admit("scope_b", "llm:egress").effect, Effect::Deny);
    }

    #[test]
    fn observe_only_records_without_enforcing() {
        let t = table(
            vec![rule("r1", "s", "c", Effect::Deny)],
            AccessConfig { default_action: Effect::Deny, observe_only: true },
        );
        let a = t.admit("s", "c");
        assert_eq!(a.effect, Effect::Deny, "the verdict is still recorded");
        assert!(a.observe_only);
        assert!(a.allowed(), "but it is not enforced");
    }

    #[test]
    fn default_config_is_deny_and_enforcing() {
        let cfg = AccessConfig::default();
        assert_eq!(cfg.default_action, Effect::Deny);
        assert!(!cfg.observe_only);
    }

    #[test]
    fn admit_is_a_pure_function() {
        let t = table(
            vec![
                rule("r1", "s", "c1", Effect::Allow),
                rule("r2", "s", "c2", Effect::Deny),
            ],
            AccessConfig::default(),
        );
        let first = (t.admit("s", "c1"), t.admit("s", "c2"), t.admit("s", "c3"));
        let second = (t.admit("s", "c1"), t.admit("s", "c2"), t.admit("s", "c3"));
        assert_eq!(first.0, second.0);
        assert_eq!(first.1, second.1);
        assert_eq!(first.2, second.2);
    }

    // ---- compile-time failures (D6) ----

    #[test]
    fn duplicate_id_is_rejected_at_compile() {
        let rules = vec![
            rule("dup", "s", "c1", Effect::Allow),
            rule("dup", "s", "c2", Effect::Deny),
        ];
        assert!(AccessTable::compile(rules, AccessConfig::default()).is_err());
    }

    #[test]
    fn empty_fields_are_rejected_at_compile() {
        assert!(AccessTable::compile(
            vec![rule("", "s", "c", Effect::Allow)],
            AccessConfig::default()
        )
        .is_err());
        assert!(AccessTable::compile(
            vec![rule("r1", "", "c", Effect::Allow)],
            AccessConfig::default()
        )
        .is_err());
        assert!(AccessTable::compile(
            vec![rule("r1", "s", "  ", Effect::Allow)],
            AccessConfig::default()
        )
        .is_err());
    }

    #[test]
    fn rules_round_trip_through_the_table() {
        let rules = vec![rule("r1", "s", "c", Effect::Allow)];
        let t = AccessTable::compile(rules.clone(), AccessConfig::default()).unwrap();
        assert_eq!(t.rules(), &rules[..]);
    }
}
