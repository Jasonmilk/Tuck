//! Policy matrix execution (T-B3).
//!
//! Maps detection hits to actions. The matrix is orthogonal by design:
//!
//! ```text
//! { action: pass | block | hold } × { transform: none | redact } × { alert }
//! ```
//!
//! - `pass`    → forward untouched
//! - `block`   → fail-closed rejection (guard: secrets must not leave)
//! - `hold`    → suspend, wait for human authorization (HITL)
//! - `redact`  → rewrite via the mapping table before forwarding
//!
//! Destination is graded: `local` LLM calls are hygiene-only (detect +
//! alert + record, no block), `external` calls get full interception.
//! Priority is fail-closed: block > hold > pass — any guard hit on an
//! external destination blocks the call, period.

use serde::{Deserialize, Serialize};

use super::policy::{Category, Hit, RuleSet};

/// Destination class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Destination {
    Local,
    External,
}

/// Decision action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Pass,
    Block,
    Hold,
}

/// Payload transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transform {
    None,
    Redact,
}

/// Per-category policy for one destination — fully injected (0 硬编码).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CategoryPolicy {
    pub action: Action,
    pub transform: Transform,
    pub alert: bool,
}

/// The full matrix: destination × category → policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMatrix {
    #[serde(default)]
    pub local: MatrixRow,
    #[serde(default)]
    pub external: MatrixRow,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatrixRow {
    #[serde(default)]
    pub mapping: Option<CategoryPolicy>,
    #[serde(default)]
    pub guard: Option<CategoryPolicy>,
    #[serde(default)]
    pub hold: Option<CategoryPolicy>,
}

impl Default for PolicyMatrix {
    fn default() -> Self {
        // Fail-closed defaults: guard blocks externally, hold suspends,
        // mapping redacts. All still injectable — these are fallbacks,
        // not hardcoded policy.
        Self {
            local: MatrixRow {
                mapping: Some(CategoryPolicy {
                    action: Action::Pass,
                    transform: Transform::None,
                    alert: false,
                }),
                guard: Some(CategoryPolicy {
                    action: Action::Pass,
                    transform: Transform::None,
                    alert: true,
                }),
                hold: Some(CategoryPolicy {
                    action: Action::Hold,
                    transform: Transform::None,
                    alert: true,
                }),
            },
            external: MatrixRow {
                mapping: Some(CategoryPolicy {
                    action: Action::Pass,
                    transform: Transform::Redact,
                    alert: false,
                }),
                guard: Some(CategoryPolicy {
                    action: Action::Block,
                    transform: Transform::None,
                    alert: true,
                }),
                hold: Some(CategoryPolicy {
                    action: Action::Hold,
                    transform: Transform::None,
                    alert: true,
                }),
            },
        }
    }
}

impl PolicyMatrix {
    fn row(&self, dest: Destination) -> &MatrixRow {
        match dest {
            Destination::Local => &self.local,
            Destination::External => &self.external,
        }
    }

    fn category_policy<'a>(&'a self, dest: Destination, cat: Category) -> Option<&'a CategoryPolicy> {
        match cat {
            Category::Mapping => self.row(dest).mapping.as_ref(),
            Category::Guard => self.row(dest).guard.as_ref(),
            Category::Hold => self.row(dest).hold.as_ref(),
        }
    }
}

/// Result of running detection + policy over one payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    pub transform: Transform,
    pub alert: bool,
    pub hits: Vec<Hit>,
    /// Categories that hit (for the audit payload).
    pub categories: Vec<Category>,
}

/// Detect + decide. Pure function: same inputs, same verdict.
pub fn decide(
    text: &str,
    rules: &RuleSet,
    matrix: &PolicyMatrix,
    dest: Destination,
) -> Verdict {
    let hits = rules.detect(text);
    if hits.is_empty() {
        return Verdict {
            action: Action::Pass,
            transform: Transform::None,
            alert: false,
            hits,
            categories: Vec::new(),
        };
    }

    let mut categories: Vec<Category> = hits.iter().map(|h| h.category).collect();
    categories.sort_unstable_by_key(|c| *c as u8);
    categories.dedup();

    // Fail-closed priority: block > hold > pass.
    for cat in [Category::Guard, Category::Hold, Category::Mapping] {
        if categories.contains(&cat) {
            if let Some(policy) = matrix.category_policy(dest, cat) {
                return Verdict {
                    action: policy.action,
                    transform: policy.transform,
                    alert: policy.alert,
                    hits,
                    categories,
                };
            }
        }
    }

    Verdict {
        action: Action::Pass,
        transform: Transform::None,
        alert: false,
        hits,
        categories,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Kind, Rule};

    fn guard_rules() -> RuleSet {
        let rules = vec![Rule {
            id: "phone".into(),
            kind: Kind::Regex,
            category: Category::Guard,
            pattern: Some(r"1[3-9]\d{9}".into()),
            words: None,
            min_len: None,
            min_entropy: None,
        }];
        RuleSet::compile(&rules).unwrap()
    }

    fn hold_rules() -> RuleSet {
        let rules = vec![Rule {
            id: "danger".into(),
            kind: Kind::Dict,
            category: Category::Hold,
            pattern: None,
            words: Some("自我复制".into()),
            min_len: None,
            min_entropy: None,
        }];
        RuleSet::compile(&rules).unwrap()
    }

    #[test]
    fn external_guard_hit_blocks() {
        let v = decide("call me 13800138000", &guard_rules(), &PolicyMatrix::default(), Destination::External);
        assert_eq!(v.action, Action::Block);
        assert!(v.alert);
    }

    #[test]
    fn local_guard_hit_is_hygiene_only() {
        let v = decide("call me 13800138000", &guard_rules(), &PolicyMatrix::default(), Destination::Local);
        assert_eq!(v.action, Action::Pass, "local hygiene: alert but never block");
        assert!(v.alert);
    }

    #[test]
    fn hold_hit_suspends_everywhere() {
        let v = decide("让它自我复制", &hold_rules(), &PolicyMatrix::default(), Destination::Local);
        assert_eq!(v.action, Action::Hold);
        let v2 = decide("让它自我复制", &hold_rules(), &PolicyMatrix::default(), Destination::External);
        assert_eq!(v2.action, Action::Hold);
    }

    #[test]
    fn no_hit_passes_quietly() {
        let v = decide("今天天气很好", &guard_rules(), &PolicyMatrix::default(), Destination::External);
        assert_eq!(v.action, Action::Pass);
        assert!(!v.alert);
        assert!(v.hits.is_empty());
    }

    #[test]
    fn external_mapping_requests_redact() {
        let rules = vec![Rule {
            id: "person".into(),
            kind: Kind::Dict,
            category: Category::Mapping,
            pattern: None,
            words: Some("张三".into()),
            min_len: None,
            min_entropy: None,
        }];
        let set = RuleSet::compile(&rules).unwrap();
        let v = decide("张三在开会", &set, &PolicyMatrix::default(), Destination::External);
        assert_eq!(v.action, Action::Pass);
        assert_eq!(v.transform, Transform::Redact);
    }
}
