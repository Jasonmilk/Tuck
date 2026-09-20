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
//! order. The body is the sequence number in lowercase hexadecimal,
//! zero-padded to *at least* [`PLACEHOLDER_MIN_DIGITS`] digits. That width is
//! a **floor, never a ceiling**: `seq` 0..=255 render as the familiar
//! four-byte `P_00`…`P_ff`, and a session that maps more entities keeps going
//! with wider placeholders (`P_100`, …) instead of colliding or wrapping.
//! Generation and parsing both derive from [`PLACEHOLDER_PREFIX`] and
//! [`PLACEHOLDER_MIN_DIGITS`], so neither side may assume the emitted width.
//! Determinism holds per session (same session, same input → identical
//! output); cross-session identity is intentionally not stable — a
//! placeholder is a session-scoped alias, not a global identifier. Short
//! placeholders honor 极致节能 (fewer tokens fed to the LLM).
//!
//! # Demap failure (honest, never silent)
//!
//! The model may split, quote or paraphrase a placeholder. When a
//! placeholder cannot be resolved, it is left as-is and counted — reported
//! as `demap_miss` in the audit entry, never swallowed, never hard-blocked.
//! A placeholder is read as one maximal run, so it is never a *prefix* of a
//! longer token: `P_100` can never be resolved as `P_10`.

use std::collections::HashMap;

/// Placeholder prefix — spelled once, read by generation and parsing alike.
///
/// Visible to the rest of the crate (the SSE carry in [`crate::gov`] scans
/// for it) so the prefix is never re-spelled outside this module.
pub(crate) const PLACEHOLDER_PREFIX: &str = "P_";

/// Placeholder body width **floor** — the single source of truth for the
/// width rule shared by generation ([`render_placeholder`]) and parsing
/// ([`parse_placeholder`]).
///
/// The body is the sequence number in lowercase hexadecimal, zero-padded to
/// *at least* this many digits. It is a floor, not a ceiling: sequences
/// `0..=0xff` render four bytes wide (`P_00`…`P_ff`) and larger sequences
/// simply take more digits (`P_100`…). Nothing may assume an emitted
/// placeholder is exactly this wide — that assumption is exactly the defect
/// this rule closes.
pub(crate) const PLACEHOLDER_MIN_DIGITS: usize = 2;

/// Render the placeholder for `seq`. The **only** place the emitted format is
/// produced; the parser derives its shape from the same constants.
fn render_placeholder(seq: u64) -> String {
    format!(
        "{PLACEHOLDER_PREFIX}{seq:0width$x}",
        width = PLACEHOLDER_MIN_DIGITS
    )
}

/// End of the maximal run of characters satisfying `pred`, starting at byte
/// offset `from`. Returns `None` when `from` is not a char boundary of
/// `text`, or past its end.
///
/// Offsets come only from [`char_indices`](str::char_indices), so the result
/// is always a char boundary.
fn run_end(text: &str, from: usize, pred: impl Fn(char) -> bool) -> Option<usize> {
    let mut end = from;
    for (off, c) in text.get(from..)?.char_indices() {
        if !pred(c) {
            break;
        }
        end = from + off + c.len_utf8();
    }
    Some(end)
}

/// Parse the placeholder beginning at `start`, the byte offset of its `P`.
///
/// Returns the candidate slice when `text[start..]` is placeholder-shaped, or
/// `None` when it is not. The body is taken as the **maximal** run of ASCII
/// hex digits — the alphabet [`render_placeholder`] emits — so a placeholder
/// is never a prefix of a longer token: `P_100` is read whole and can never
/// be mistaken for `P_10`.
///
/// A maximal run of ASCII alphanumerics is also accepted as a *candidate*
/// when the hex run is shorter than [`PLACEHOLDER_MIN_DIGITS`]: the model may
/// paraphrase a placeholder into e.g. `P_zz`, which resolves to nothing but
/// must still be counted as a `demap_miss` rather than passed through
/// silently.
///
/// Never panics: every slice goes through [`str::get`], so an offset landing
/// inside a multi-byte character yields `None` (not a placeholder), never a
/// mid-character byte-slice abort.
fn parse_placeholder(text: &str, start: usize) -> Option<&str> {
    let after_prefix = start + PLACEHOLDER_PREFIX.len();
    // The generated format first: the maximal hex run.
    let hex_end = run_end(text, after_prefix, |c| c.is_ascii_hexdigit())?;
    if hex_end - after_prefix >= PLACEHOLDER_MIN_DIGITS {
        return text.get(start..hex_end);
    }
    // A paraphrased token (`P_zz`): unresolvable, but still an honest miss.
    let word_end = run_end(text, after_prefix, |c| c.is_ascii_alphanumeric())?;
    if word_end - after_prefix >= PLACEHOLDER_MIN_DIGITS {
        return text.get(start..word_end);
    }
    None
}

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
    ///
    /// Placeholders are never reused: the width grows with the sequence
    /// (see [`render_placeholder`]), so a session that maps more than 256
    /// entities does not have to wrap, collide, or fail.
    pub fn placeholder(&mut self, entity: &str) -> String {
        if let Some(p) = self.forward.get(entity) {
            return p.clone();
        }
        let p = render_placeholder(self.seq);
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
    ///
    /// A token is unresolvable when it is placeholder-shaped — `P_` plus a
    /// body of at least [`PLACEHOLDER_MIN_DIGITS`] characters (hex, or an
    /// alphanumeric paraphrase such as `P_zz`) — yet absent from this
    /// session's table; it is emitted verbatim and counted. A wider token that
    /// merely *starts* like a smaller placeholder (`P_100` vs `P_10`) is read
    /// as one token, so it is never resolved as the smaller one: it either
    /// resolves to its own entity or counts as a `demap_miss`.
    pub fn demap(&self, text: &str) -> (String, u64) {
        let mut out = String::with_capacity(text.len());
        let mut misses = 0u64;
        let mut cursor = 0usize;

        while let Some(found) = text.get(cursor..).and_then(|t| t.find(PLACEHOLDER_PREFIX)) {
            let start = cursor + found;
            match parse_placeholder(text, start) {
                Some(candidate) => {
                    // Everything before the token is literal text.
                    if let Some(literal) = text.get(cursor..start) {
                        out.push_str(literal);
                    }
                    match self.reverse.get(candidate) {
                        Some(entity) => out.push_str(entity),
                        None => {
                            // Left verbatim and counted — never dropped.
                            out.push_str(candidate);
                            misses += 1;
                        }
                    }
                    cursor = start + candidate.len();
                }
                None => {
                    // Not placeholder-shaped: too few body characters, or the
                    // window ends inside a multi-byte character. Keep the
                    // prefix verbatim and resume right after it.
                    let after = start + PLACEHOLDER_PREFIX.len();
                    match text.get(cursor..after) {
                        Some(literal) => {
                            out.push_str(literal);
                            cursor = after;
                        }
                        // Unreachable (both offsets are char boundaries);
                        // never drop text if it somehow happens.
                        None => break,
                    }
                }
            }
        }
        if let Some(tail) = text.get(cursor..) {
            out.push_str(tail);
        }
        (out, misses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix::{Action, Destination, PolicyMatrix, Transform, decide};
    use crate::policy::{Category, Kind, Rule, RuleSet};

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

    /// Regression: `P_` followed by a multi-byte character used to byte-slice
    /// the 4-byte window and abort with "byte index N is not a char boundary".
    /// Under the table mutex that poisoned every later request (and aborts the
    /// process in release). It must be an ordinary non-placeholder instead.
    #[test]
    fn demap_does_not_panic_on_multibyte_after_prefix() {
        let mut table = MappingTable::new();
        table.placeholder("张三"); // P_00

        for input in ["P_中", "P_。", "P_😀", "前缀P_中后缀", "P_00中"] {
            let (out, misses) = table.demap(input);
            if input == "P_00中" {
                assert_eq!(out, "张三中", "{input}: real placeholder must still resolve");
            } else {
                assert_eq!(out, input, "{input}: not a placeholder, verbatim");
            }
            assert_eq!(misses, 0, "{input}: nothing placeholder-shaped to miss");
        }
    }

    /// Regression: a session past 256 entities emits `P_100`. It must resolve
    /// to its own entity — never to `P_10`'s (silent wrong-entity substitution).
    #[test]
    fn demap_resolves_wide_placeholder_to_its_own_entity() {
        let mut table = MappingTable::new();
        let issued: Vec<String> = (0..257u64).map(|i| table.placeholder(&format!("E{i}"))).collect();

        assert_eq!(issued[0], "P_00");
        assert_eq!(issued[15], "P_0f");
        assert_eq!(issued[16], "P_10"); // owns E16
        assert_eq!(issued[255], "P_ff");
        assert_eq!(issued[256], "P_100"); // owns E256

        let (out, misses) = table.demap("P_100");
        assert_eq!(out, "E256", "wide placeholder restores its own entity");
        assert_eq!(misses, 0);
        assert!(!out.contains("E16"), "must never alias to the P_10 owner");

        let (out, misses) = table.demap("P_0fP_10P_100");
        assert_eq!(out, "E15E16E256");
        assert_eq!(misses, 0);
    }

    /// End-to-end through the public API: a session past the 256th entity
    /// emits five-byte placeholders and still round-trips exactly.
    #[test]
    fn redact_demap_round_trip_past_256_entities() {
        let entities: Vec<String> = (0..257).map(|i| format!("E{i}")).collect();
        let text = entities.join(",");
        let mut hits = Vec::new();
        let mut cursor = 0usize;
        for entity in &entities {
            let start = cursor;
            let end = start + entity.len();
            hits.push(crate::policy::Hit {
                rule_id: "test".into(),
                category: Category::Mapping,
                start,
                end,
                matched: entity.clone(),
            });
            cursor = end + 1; // skip the ','
        }

        let mut table = MappingTable::new();
        let (redacted, repls) = table.redact(&text, &hits);
        assert!(redacted.contains("P_00,"));
        assert!(redacted.contains("P_ff,"));
        assert!(redacted.ends_with("P_100"), "257th entity is five bytes wide");
        assert_eq!(repls.len(), 257);
        assert!(!redacted.contains("E256"), "entity never leaves unredacted");

        let (restored, misses) = table.demap(&redacted);
        assert_eq!(restored, text, "every entity round-trips");
        assert_eq!(misses, 0);
    }

    /// Regression: an unissued wide token in a small table is a `demap_miss`,
    /// and in particular is not silently read as its 2-digit prefix.
    #[test]
    fn unissued_wide_placeholder_is_a_miss_never_an_alias() {
        let mut table = MappingTable::new();
        for i in 0..17u64 {
            table.placeholder(&format!("E{i}")); // P_00..P_10; P_10 owns E16
        }

        let (out, misses) = table.demap("P_100");
        assert_eq!(out, "P_100", "unknown wide token stays verbatim");
        assert_eq!(misses, 1, "and is counted, not swallowed");
        assert!(!out.contains("E16"), "must never resolve to the P_10 owner");

        // Sanity: the 2-digit token itself is intact.
        let (out, misses) = table.demap("P_10");
        assert_eq!(out, "E16");
        assert_eq!(misses, 0);
    }

    /// The whole 2-digit space still round-trips to its own entity.
    #[test]
    fn two_digit_placeholders_resolve_to_their_own_entities() {
        let mut table = MappingTable::new();
        let issued: Vec<String> = (0..256u64).map(|i| table.placeholder(&format!("E{i}"))).collect();
        assert_eq!(issued[0], "P_00");
        assert_eq!(issued[15], "P_0f");
        assert_eq!(issued[16], "P_10");
        assert_eq!(issued[255], "P_ff");

        for (i, placeholder) in issued.iter().enumerate() {
            let (out, misses) = table.demap(placeholder);
            assert_eq!(out, format!("E{i}"), "{placeholder} must restore E{i}");
            assert_eq!(misses, 0, "{placeholder} resolves");
        }
    }

    #[test]
    fn demap_miss_counts_unknown_and_paraphrased_placeholders() {
        let mut table = MappingTable::new();
        table.placeholder("张三"); // P_00

        // Shape-valid hex suffix that was never issued.
        let (out, misses) = table.demap("P_ff");
        assert_eq!(out, "P_ff");
        assert_eq!(misses, 1);

        // Non-hex paraphrase (`P_zz`): unresolvable, still an honest miss.
        let (out, misses) = table.demap("P_zz");
        assert_eq!(out, "P_zz");
        assert_eq!(misses, 1);

        // Nothing placeholder-shaped after the prefix: not a miss.
        let (out, misses) = table.demap("P_");
        assert_eq!(out, "P_");
        assert_eq!(misses, 0);
        let (out, misses) = table.demap("P_z"); // below the width floor
        assert_eq!(out, "P_z");
        assert_eq!(misses, 0);

        // A real placeholder followed by a non-hex letter still resolves.
        let (out, misses) = table.demap("P_00z");
        assert_eq!(out, "张三z");
        assert_eq!(misses, 0);
    }

    /// Generation and parsing share one width rule: every placeholder the
    /// table issues is exactly [`render_placeholder`] of its sequence.
    #[test]
    fn generation_matches_the_shared_width_rule() {
        let mut table = MappingTable::new();
        for seq in 0..300u64 {
            assert_eq!(table.placeholder(&format!("E{seq}")), render_placeholder(seq));
        }
        assert_eq!(render_placeholder(0), "P_00");
        assert_eq!(render_placeholder(0x0f), "P_0f");
        assert_eq!(render_placeholder(0x10), "P_10");
        assert_eq!(render_placeholder(0xff), "P_ff");
        assert_eq!(render_placeholder(0x100), "P_100");
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
