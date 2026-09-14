//! Access admission tests (H-1 table, H-2 request admission).
//!
//! Kept as an integration test so `access.rs` stays under the 400-line
//! decoupling limit. The behaviour under test is unchanged — only the import
//! path differs.

use tuck_gateway::capability::Target;
use tuck_gateway::{AccessConfig, AccessRule, AccessTable, Effect};


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

// ---- H-2: admitting a concrete request ----

fn target<'a>(supplier: Option<&'a str>, model: Option<&'a str>) -> Target<'a> {
    Target { supplier, model }
}

#[test]
fn request_is_admitted_when_every_capability_is_allowed() {
    let t = table(
        vec![
            rule("r_egress", "s", "llm:egress", Effect::Allow),
            rule("r_supplier", "s", "llm:invoke:agnes", Effect::Allow),
            rule("r_model", "s", "llm:model:m1", Effect::Allow),
        ],
        AccessConfig::default(),
    );
    let a = t.admit_request(Some("s"), &target(Some("agnes"), Some("m1")));
    assert_eq!(a.effect, Effect::Allow);
    assert_eq!(a.rule_id.as_deref(), Some("r_egress"));
    assert!(a.allowed());
}

#[test]
fn denied_supplier_stops_the_call_and_names_the_rule() {
    let t = table(
        vec![
            rule("r_egress", "s", "llm:egress", Effect::Allow),
            rule("r_supplier", "s", "llm:invoke:agnes", Effect::Deny),
        ],
        AccessConfig::default(),
    );
    let a = t.admit_request(Some("s"), &target(Some("agnes"), None));
    assert_eq!(a.effect, Effect::Deny);
    assert_eq!(a.rule_id.as_deref(), Some("r_supplier"));
    assert!(!a.allowed());
}

#[test]
fn denied_model_stops_the_call() {
    let t = table(
        vec![
            rule("r_egress", "s", "llm:egress", Effect::Allow),
            rule("r_model", "s", "llm:model:m1", Effect::Deny),
        ],
        AccessConfig::default(),
    );
    let a = t.admit_request(Some("s"), &target(None, Some("m1")));
    assert_eq!(a.effect, Effect::Deny);
    assert!(!a.allowed());
}

#[test]
fn missing_egress_denies_even_when_the_supplier_is_allowed() {
    // Least privilege: a supplier rule does not imply the right to egress.
    let t = table(
        vec![rule("r_supplier", "s", "llm:invoke:agnes", Effect::Allow)],
        AccessConfig::default(),
    );
    let a = t.admit_request(Some("s"), &target(Some("agnes"), None));
    assert_eq!(a.effect, Effect::Deny);
    assert_eq!(a.rule_id, None, "this denial came from the default, not a rule");
}

#[test]
fn a_call_without_supplier_or_model_is_gated_on_egress_alone() {
    let t = table(
        vec![rule("r_egress", "s", "llm:egress", Effect::Allow)],
        AccessConfig::default(),
    );
    assert_eq!(t.admit_request(Some("s"), &target(None, None)).effect, Effect::Allow);
}

#[test]
fn a_caller_without_scope_is_denied_outright() {
    // Even with default_action relaxed: there is nothing to look up.
    let t = table(
        vec![rule("r_egress", "s", "llm:egress", Effect::Allow)],
        AccessConfig { default_action: Effect::Allow, observe_only: false },
    );
    let a = t.admit_request(None, &target(None, None));
    assert_eq!(a.effect, Effect::Deny);
    assert_eq!(a.rule_id, None);
}

#[test]
fn blank_scope_is_treated_as_no_scope() {
    let t = table(
        vec![rule("r_egress", "s", "llm:egress", Effect::Allow)],
        AccessConfig::default(),
    );
    assert_eq!(t.admit_request(Some("   "), &target(None, None)).effect, Effect::Deny);
}

#[test]
fn observe_mode_records_a_denial_without_enforcing_it() {
    let t = table(
        vec![rule("r_egress", "s", "llm:egress", Effect::Deny)],
        AccessConfig { default_action: Effect::Deny, observe_only: true },
    );
    let a = t.admit_request(Some("s"), &target(None, None));
    assert_eq!(a.effect, Effect::Deny, "the verdict is still recorded");
    assert!(a.allowed(), "but it is not enforced");
}

#[test]
fn unknown_supplier_falls_through_to_the_default() {
    let t = table(
        vec![
            rule("r_egress", "s", "llm:egress", Effect::Allow),
            rule("r_other", "s", "llm:invoke:openrouter", Effect::Allow),
        ],
        AccessConfig::default(),
    );
    let a = t.admit_request(Some("s"), &target(Some("agnes"), None));
    assert_eq!(a.effect, Effect::Deny);
    assert_eq!(a.rule_id, None);
}
