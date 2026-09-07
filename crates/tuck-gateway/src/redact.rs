//! Semantic redaction — entity → placeholder mapping (T-B4).
//!
//! The second pillar of Tuck's content governance. Before an external
//! payload leaves, mapping-category entities are rewritten to deterministic
//! session placeholders; on the way back, placeholders are restored to the
//! original entities.
//!
//! # Session scoping (Rosetta-stone rule)
//!
//! The table lives **per session, in memory only**. The same entity always
//! maps to the same placeholder within a session (the model must not see two
//! placeholders for one person). It is the highest-sensitivity asset in the
//! ecosystem: never logged, never printed, encrypted at rest (Vault), and
//! **never part of the audit chain** — the chain stores only the redacted
//! form plus placeholder references.
//!
//! # Placeholder derivation (deterministic + frugal)
//!
//! Placeholders are short: `P_00`, `P_01`, … assigned in first-appearance
//! order. Determinism holds per session (same session, same input →
//! identical output); cross-session identity is intentionally not stable —
//! a placeholder is a session-scoped alias, not a global identifier.
//! Short placeholders honor 极致节能 (fewer tokens fed to the LLM).
//!
//! # Demap failure (honest, never silent)
//!
//! The model may split, quote or paraphrase a placeholder. When a
//! placeholder cannot be resolved, it is left as-is and counted — reported
//! as `demap_miss` in the audit entry, never swallowed, never hard-blocked.

use std::collections::HashMap;

/// One redaction event (used by the audit payload — redacted form only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    /// The placeholder that replaced the entity.
    pub placeholder: String,
    /// Position in the redacted text.
    pub start: usize,
    pub end: usize,
}

/// Session-scoped entity → placeholder table.
#[derive(Debug, Default)]
pub struct MappingTable {
    /// Entity (original text) → placeholder.
    forward: HashMap<String, String>,
    /// Placeholder → entity.
    reverse: HashMap<String, String>,
    /// Next placeholder index (deterministic derivation, no UUID).
    seq: u64,
}

impl MappingTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve an entity to its placeholder, assigning a new one on first
    /// sight. Same entity → same placeholder within this session.
    pub fn placeholder(&mut self, entity: &str) -> String {
        if let Some(p) = self.forward.get(entity) {
            return p.clone();
        }
        let p = format!("P_{:02x}", self.seq);
        self.seq += 1;
        self.forward.insert(entity.to_string(), p.clone());
        self.reverse.insert(p.clone(), entity.to_string());
        p
    }

    /// Rewrite mapping hits to placeholders.
    ///
    /// Hits must be sorted by position (the detector guarantees it). The
    /// output text contains no original entity; the returned replacements
    /// carry only placeholders and positions — safe for the audit chain.
    pub fn redact(&mut self, text: &str, hits: &[crate::policy::Hit]) -> (String, Vec<Replacement>) {
        if hits.is_empty() {
            return (text.to_string(), Vec::new());
        }
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        let mut replacements = Vec::new();
        for h in hits {
            if h.start < cursor {
                continue; // overlapping hits: first match wins
            }
            out.push_str(&text[cursor..h.start]);
            let placeholder = self.placeholder(&h.matched);
            let start = out.len();
            out.push_str(&placeholder);
            replacements.push(Replacement {
                placeholder: placeholder.clone(),
                start,
                end: start + placeholder.len(),
            });
            cursor = h.end;
        }
        out.push_str(&text[cursor..]);
        (out, replacements)
    }

    /// Restore placeholders to original entities.
    ///
    /// Returns the restored text and the count of unresolvable placeholders
    /// (`demap_miss`) — never silently dropped, never hard-blocked.
    pub fn demap(&self, text: &str) -> (String, u64) {
        let mut out = String::with_capacity(text.len());
        let mut misses = 0u64;
        let mut rest = text;
        while let Some(start) = rest.find("P_") {
            // Placeholders are P_ + 2 hex chars — bounded parse.
            let cand = &rest[start..rest.len().min(start + 4)];
            let placeholder = if cand.len() == 4 && cand[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                cand
            } else {
                // Not a placeholder shape; keep the prefix and continue.
                out.push_str(&rest[..start + 2]);
                rest = &rest[start + 2..];
                continue;
            };
            out.push_str(&rest[..start]);
            match self.reverse.get(placeholder) {
                Some(entity) => out.push_str(entity),
                None => {
                    out.push_str(placeholder);
                    misses += 1;
                }
            }
            rest = &rest[start + placeholder.len()..];
        }
        out.push_str(rest);
        (out, misses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix::{Action, Destination, PolicyMatrix, Transform, Verdict, decide};
    use crate::policy::{Category, Hit, Kind, Rule, RuleSet};

    fn mapping_rules() -> RuleSet {
        let rules = vec![Rule {
            id: "person".into(),
            kind: Kind::Dict,
            category: Category::Mapping,
            pattern: None,
            words: Some("张三,李四".into()),
            min_len: None,
            min_entropy: None,
        }];
        RuleSet::compile(&rules).unwrap()
    }

    #[test]
    fn same_entity_same_placeholder() {
        let mut table = MappingTable::new();
        let a = table.placeholder("张三");
        let b = table.placeholder("张三");
        assert_eq!(a, b);
        assert_eq!(a, "P_00");
        assert_eq!(table.placeholder("李四"), "P_01");
    }

    #[test]
    fn redact_removes_entities_adds_placeholders() {
        let rules = mapping_rules();
        let v = decide("张三叫李四开会", &rules, &PolicyMatrix::default(), Destination::External);
        assert_eq!(v.action, Action::Pass);
        assert_eq!(v.transform, Transform::Redact);

        let mut table = MappingTable::new();
        let (redacted, repls) = table.redact("张三叫李四开会", &v.hits);
        assert!(!redacted.contains("张三"));
        assert!(!redacted.contains("李四"));
        assert_eq!(redacted, "P_00叫P_01开会");
        assert_eq!(repls.len(), 2);
        // Placeholders only — original entities absent from replacements.
        assert!(repls.iter().all(|r| r.placeholder.starts_with("P_")));
    }

    #[test]
    fn demap_restores_originals() {
        let mut table = MappingTable::new();
        table.placeholder("张三");
        table.placeholder("李四");
        let (restored, misses) = table.demap("P_00叫P_01开会");
        assert_eq!(restored, "张三叫李四开会");
        assert_eq!(misses, 0);
    }

    #[test]
    fn demap_miss_is_counted_not_swallowed() {
        let mut table = MappingTable::new();
        table.placeholder("张三");
        let (restored, misses) = table.demap("P_00说P_ff是假的");
        assert_eq!(restored, "张三说P_ff是假的", "unresolvable stays as-is");
        assert_eq!(misses, 1);
    }

    #[test]
    fn full_flow_external_redact_then_restore() {
        let rules = mapping_rules();
        let mut table = MappingTable::new();

        // Outbound.
        let v = decide("张三的号码是 13800138000", &rules, &PolicyMatrix::default(), Destination::External);
        let (out, _) = table.redact("张三的号码是 13800138000", &v.hits);
        assert_eq!(out, "P_00的号码是 13800138000");

        // Model answers with the placeholder (paraphrased slightly).
        let (back, misses) = table.demap("P_00说好的");
        assert_eq!(back, "张三说好的");
        assert_eq!(misses, 0);
    }

    #[test]
    fn deterministic_same_input_same_output() {
        let rules = mapping_rules();
        let text = "张三和李四都在";
        let mut t1 = MappingTable::new();
        let mut t2 = MappingTable::new();
        let v = decide(text, &rules, &PolicyMatrix::default(), Destination::External);
        let (o1, _) = t1.redact(text, &v.hits);
        let (o2, _) = t2.redact(text, &v.hits);
        assert_eq!(o1, o2);
    }

    #[test]
    fn hits_need_start_end_guard_against_overlap() {
        // Two hits overlapping: dict "张三" and a longer regex over same text.
        let rules = RuleSet::compile(&[
            Rule {
                id: "p".into(),
                kind: Kind::Dict,
                category: Category::Mapping,
                pattern: None,
                words: Some("张三".into()),
                min_len: None,
                min_entropy: None,
            },
            Rule {
                id: "r".into(),
                kind: Kind::Regex,
                category: Category::Mapping,
                pattern: Some(r"张三丰".into()),
                words: None,
                min_len: None,
                min_entropy: None,
            },
        ])
        .unwrap();
        let hits = rules.detect("张三丰");
        let mut table = MappingTable::new();
        let (out, _) = table.redact("张三丰", &hits);
        // First match wins; no double-replacement corruption.
        assert!(out.starts_with("P_"));
        assert!(!out.contains("张三"));
    }
}
