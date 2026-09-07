//! Input detection engine (T-B2) — objective predicates only.
//!
//! Detection is pure string arithmetic: regex, dictionary substrings and
//! entropy heuristics. **Tuck never judges meaning** — this engine answers
//! one question: *does the payload match a configured objective pattern?*
//!
//! # Three rule categories (user-confirmed vocabulary)
//!
//! | category | meaning | policy intent |
//! |---|---|---|
//! | `mapping` | entity → placeholder redaction | pass + redact |
//! | `guard`   | secrets that must not leave | block + alert |
//! | `hold`    | dangerous behavior | hold + alert (HITL) |
//!
//! Categories are labels carried by hits; the policy stage (T-B3) decides
//! actions. Zero hardcoding: every rule is injected as JSON config.
//!
//! # Determinism
//!
//! Rules are evaluated in config order; hits are returned in text position
//! order. Same input + same rules → same hits, byte for byte.

use serde::{Deserialize, Serialize};

/// Rule category — the three governance tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Mapping,
    Guard,
    Hold,
}

/// Matching strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Substring present in a fixed word list.
    Dict,
    /// Regular expression (compiled once at load).
    Regex,
    /// High-entropy token (secrets: API keys, tokens).
    Entropy,
}

/// One detection rule — fully injected, no magic values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub kind: Kind,
    pub category: Category,
    /// Dict words / regex source. Ignored for `entropy`.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Words for dict rules (split on commas).
    #[serde(default)]
    pub words: Option<String>,
    /// Entropy rules: minimum token length and Shannon bits per char.
    #[serde(default)]
    pub min_len: Option<usize>,
    #[serde(default)]
    pub min_entropy: Option<f64>,
}

/// One detection hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hit {
    pub rule_id: String,
    pub category: Category,
    pub start: usize,
    pub end: usize,
    pub matched: String,
}

/// Compiled rule set.
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    meta: Rule,
    regex: Option<regex::Regex>,
    words: Vec<String>,
}

impl RuleSet {
    /// Compile rules once at load. Invalid regex is a hard error —
    /// fail-closed at configuration time, not at request time.
    pub fn compile(rules: &[Rule]) -> Result<Self, String> {
        let mut out = Vec::with_capacity(rules.len());
        for r in rules {
            let regex = match r.kind {
                Kind::Regex => {
                    let pat = r.pattern.as_deref().ok_or_else(|| {
                        format!("rule {}: regex kind requires pattern", r.id)
                    })?;
                    Some(regex::Regex::new(pat).map_err(|e| format!("rule {}: {e}", r.id))?)
                }
                _ => None,
            };
            let words = match r.kind {
                Kind::Dict => r
                    .words
                    .as_deref()
                    .map(|w| w.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            out.push(CompiledRule {
                meta: r.clone(),
                regex,
                words,
            });
        }
        Ok(RuleSet { rules: out })
    }

    /// Run every rule over `text`. Hits are deduplicated per rule
    /// (first match region wins) and sorted by position.
    pub fn detect(&self, text: &str) -> Vec<Hit> {
        let mut hits = Vec::new();
        for rule in &self.rules {
            match rule.meta.kind {
                Kind::Dict => {
                    for w in &rule.words {
                        if let Some(pos) = text.find(w.as_str()) {
                            hits.push(Hit {
                                rule_id: rule.meta.id.clone(),
                                category: rule.meta.category,
                                start: pos,
                                end: pos + w.len(),
                                matched: w.clone(),
                            });
                        }
                    }
                }
                Kind::Regex => {
                    if let Some(re) = &rule.regex {
                        for m in re.find_iter(text) {
                            hits.push(Hit {
                                rule_id: rule.meta.id.clone(),
                                category: rule.meta.category,
                                start: m.start(),
                                end: m.end(),
                                matched: m.as_str().to_string(),
                            });
                        }
                    }
                }
                Kind::Entropy => {
                    let min_len = rule.meta.min_len.unwrap_or(16);
                    let min_entropy = rule.meta.min_entropy.unwrap_or(3.5);
                    for (start, end) in high_entropy_runs(text, min_len, min_entropy) {
                        hits.push(Hit {
                            rule_id: rule.meta.id.clone(),
                            category: rule.meta.category,
                            start,
                            end,
                            matched: text[start..end].to_string(),
                        });
                    }
                }
            }
        }
        hits.sort_by_key(|h| (h.start, h.end));
        hits
    }
}

/// Shannon entropy (bits per char) over byte values.
fn shannon(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let bytes = text.as_bytes();
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Find maximal runs of high-entropy characters.
///
/// Secrets (API keys, tokens) are ASCII alphabets/digits/symbols. Chinese
/// and other non-ASCII text is byte-diverse but is **not** a secret shape,
/// so it acts as a token boundary: only contiguous ASCII runs are entropy
/// scored. This keeps the predicate objective and physically grounded.
fn high_entropy_runs(text: &str, min_len: usize, min_entropy: f64) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut runs: Vec<(usize, usize)> = Vec::new();
    // Split into contiguous ASCII runs.
    let mut start: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        let ascii = b.is_ascii_alphanumeric() || b.is_ascii_punctuation();
        match (ascii, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min_len && shannon(&text[s..i]) >= min_entropy {
                    runs.push((s, i));
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        let e = bytes.len();
        if e - s >= min_len && shannon(&text[s..]) >= min_entropy {
            runs.push((s, e));
        }
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, kind: Kind, category: Category) -> Rule {
        Rule {
            id: id.to_string(),
            kind,
            category,
            pattern: None,
            words: None,
            min_len: None,
            min_entropy: None,
        }
    }

    #[test]
    fn dict_hit_detects_and_labels_category() {
        let rules = vec![Rule {
            words: Some("张三,李四".into()),
            ..rule("person", Kind::Dict, Category::Mapping)
        }];
        let set = RuleSet::compile(&rules).unwrap();
        let hits = set.detect("我是张三，电话是 13800138000");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "person");
        assert_eq!(hits[0].category, Category::Mapping);
        assert_eq!(&hits[0].matched, "张三");
    }

    #[test]
    fn regex_hit_finds_all_matches() {
        let rules = vec![Rule {
            pattern: Some(r"1[3-9]\d{9}".into()),
            ..rule("phone", Kind::Regex, Category::Guard)
        }];
        let set = RuleSet::compile(&rules).unwrap();
        let hits = set.detect("a:13800138000 b:13912345678");
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.category == Category::Guard));
    }

    #[test]
    fn entropy_detects_secret_like_token() {
        let rules = vec![Rule {
            min_len: Some(24),
            min_entropy: Some(3.5),
            ..rule("secret", Kind::Entropy, Category::Guard)
        }];
        let set = RuleSet::compile(&rules).unwrap();
        let hits = set.detect("token=Zk9xQ2VrM1JwT0FydWJhbktleTEyMzQ1Ng==");
        assert!(!hits.is_empty(), "high-entropy base64 token must hit");
    }

    #[test]
    fn entropy_ignores_plain_text() {
        let rules = vec![Rule {
            min_len: Some(24),
            min_entropy: Some(3.5),
            ..rule("secret", Kind::Entropy, Category::Guard)
        }];
        let set = RuleSet::compile(&rules).unwrap();
        let hits = set.detect("今天天气很好我们出去散步吧聊聊天");
        assert!(hits.is_empty(), "low-entropy Chinese text must not hit");
    }

    #[test]
    fn invalid_regex_fails_at_compile() {
        let rules = vec![Rule {
            pattern: Some("(unclosed".into()),
            ..rule("bad", Kind::Regex, Category::Guard)
        }];
        assert!(RuleSet::compile(&rules).is_err());
    }

    #[test]
    fn hits_sorted_by_position() {
        let rules = vec![
            Rule {
                words: Some("甲,乙".into()),
                ..rule("d1", Kind::Dict, Category::Mapping)
            },
            Rule {
                pattern: Some(r"\d+".into()),
                ..rule("r1", Kind::Regex, Category::Guard)
            },
        ];
        let set = RuleSet::compile(&rules).unwrap();
        let hits = set.detect("乙 123 甲");
        assert!(hits.windows(2).all(|w| w[0].start <= w[1].start));
    }
}
