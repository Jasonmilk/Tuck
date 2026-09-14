//! Capability vocabulary for the access gate (H-3).
//!
//! Shape follows the CI-144 three-part name `domain:action[:qualifier]`
//! (CAPABILITY-13 §2.1), so the gate speaks the ecosystem's existing
//! language instead of inventing a parallel namespace (`ADR-0005` D3).
//!
//! The constants here are **protocol vocabulary, not tuning values** — they
//! are the names of the things being gated, and they change only when the
//! protocol does.

/// Domain covering every outbound LLM capability.
pub const DOMAIN: &str = "llm";

/// Separator of the three-part capability name.
pub const SEP: &str = ":";

/// Actions inside the `llm` domain.
pub mod action {
    /// Outbound LLM calls at all (the broadest gate).
    pub const EGRESS: &str = "egress";
    /// Reaching a specific supplier.
    pub const INVOKE: &str = "invoke";
    /// Calling a specific model.
    pub const MODEL: &str = "model";
}

/// Broadest capability: this scope may make outbound LLM calls at all.
pub fn egress() -> String {
    format!("{}{}{}", DOMAIN, SEP, action::EGRESS)
}

/// Supplier-scoped: this scope may reach `supplier`.
pub fn invoke(supplier: &str) -> String {
    format!("{}{}{}{}{}", DOMAIN, SEP, action::INVOKE, SEP, supplier)
}

/// Model-scoped: this scope may call `model`.
pub fn model(model: &str) -> String {
    format!("{}{}{}{}{}", DOMAIN, SEP, action::MODEL, SEP, model)
}

/// What one call needs.
///
/// Derived from the request itself, never declared by the caller: a capability
/// the caller hands us is a *request*, not a fact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Target<'a> {
    /// Resolved supplier (`X-Route-Tier` → `upstreams[].tier`).
    pub supplier: Option<&'a str>,
    /// Model taken from the request body (physical fact, not config).
    pub model: Option<&'a str>,
}

/// Capabilities a call requires.
///
/// Egress is always required. The finer dimensions are added only when the
/// request actually carries them — a call with no model is not gated on a
/// model, and blank values are not promoted into capabilities.
pub fn required(t: &Target) -> Vec<String> {
    let mut out = Vec::with_capacity(3);
    out.push(egress());
    if let Some(s) = t.supplier {
        if !s.trim().is_empty() {
            out.push(invoke(s));
        }
    }
    if let Some(m) = t.model {
        if !m.trim().is_empty() {
            out.push(model(m));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_is_domain_plus_action() {
        assert_eq!(egress(), "llm:egress");
    }

    #[test]
    fn invoke_and_model_carry_their_qualifier() {
        assert_eq!(invoke("agnes"), "llm:invoke:agnes");
        assert_eq!(model("deepseek-chat"), "llm:model:deepseek-chat");
    }

    #[test]
    fn required_always_includes_egress() {
        assert_eq!(required(&Target::default()), vec!["llm:egress".to_string()]);
    }

    #[test]
    fn required_adds_a_dimension_only_when_present() {
        let r = required(&Target {
            supplier: Some("agnes"),
            model: Some("m1"),
        });
        assert_eq!(
            r,
            vec![
                "llm:egress".to_string(),
                "llm:invoke:agnes".to_string(),
                "llm:model:m1".to_string(),
            ]
        );
    }

    #[test]
    fn blank_values_are_not_promoted_into_capabilities() {
        let r = required(&Target {
            supplier: Some("  "),
            model: Some(""),
        });
        assert_eq!(r, vec!["llm:egress".to_string()]);
    }

    #[test]
    fn required_is_deterministic() {
        let t = Target {
            supplier: Some("openrouter"),
            model: None,
        };
        assert_eq!(required(&t), required(&t));
    }
}
