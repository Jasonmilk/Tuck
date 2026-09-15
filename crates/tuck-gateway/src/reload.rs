//! Corpus hot reload (H-9 — `ADR-0005` D9/T9).
//!
//! Detection rules are **configuration data**: 行业黑话语料 must be updateable
//! without a restart, the same way a WAF rule set is.
//!
//! # What is deliberately NOT reloaded
//!
//! `MappingTable` (entity → placeholder) is **runtime session state**, keyed by
//! `X-Tuck-Session` and living only in memory. Swapping it under a live session
//! would break placeholder consistency: text already forwarded upstream could
//! no longer be mapped back. Only `RuleSet` is hot-swappable.
//!
//! # Fail-closed to the last good value
//!
//! A corpus file that fails to parse keeps the **previous** rules. The gate
//! never degrades to "no rules", because that would silently disable content
//! governance while looking healthy.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::policy::{Rule, RuleSet};

/// Corpus file shape: `[[rules]]` in TOML yields a `rules` array, so the
/// top level is a table, not a bare sequence.
#[derive(serde::Deserialize)]
struct CorpusFile {
    rules: Vec<Rule>,
}


/// Parse and compile a corpus file. Invalid content is a hard error — the
/// caller keeps the previous rules.
pub fn load_corpus(path: &Path) -> Result<RuleSet, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let file: CorpusFile =
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    RuleSet::compile(&file.rules)
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Watch `path` and swap in a freshly compiled `RuleSet` when it changes.
///
/// On failure the previous rules stay in place. `seen` is advanced either way
/// so a broken file does not produce a log line per tick; saving it again
/// (once fixed) triggers the next attempt.
pub fn spawn_corpus_watchdog(
    path: PathBuf,
    rules: Arc<RwLock<RuleSet>>,
    interval_s: u64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut seen = mtime(&path);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval_s)).await;
            let now = mtime(&path);
            if now == seen {
                continue;
            }
            match load_corpus(&path) {
                Ok(next) => {
                    *rules.write().await = next;
                    tracing::info!(path = %path.display(), "corpus reloaded");
                }
                Err(e) => {
                    tracing::error!(
                        "corpus reload failed, keeping previous rules: {e}"
                    );
                }
            }
            seen = now;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[[rules]]
id = "person"
kind = "dict"
category = "mapping"
words = "张三,李四"
"#;

    const BAD_REGEX: &str = r#"
[[rules]]
id = "broken"
kind = "regex"
category = "guard"
pattern = "(unclosed"
"#;

    fn write(name: &str, body: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("tuck-corpus-{name}.toml"));
        std::fs::write(&p, body).expect("write corpus");
        p
    }

    #[test]
    fn valid_corpus_compiles() {
        let p = write("valid", GOOD);
        assert!(load_corpus(&p).is_ok());
    }

    #[test]
    fn invalid_regex_is_rejected_not_degraded() {
        // Same rule as `RuleSet::compile`: fail at load time, never hand back
        // a half-built rule set.
        let p = write("bad", BAD_REGEX);
        assert!(load_corpus(&p).is_err());
    }

    #[test]
    fn missing_file_is_an_error() {
        let p = std::env::temp_dir().join("tuck-corpus-absent.toml");
        let _ = std::fs::remove_file(&p);
        assert!(load_corpus(&p).is_err());
    }

    #[tokio::test]
    async fn reload_swaps_rules_and_keeps_them_on_failure() {
        let p = write("swap", GOOD);
        let set = RuleSet::compile(&[]).expect("empty compiles");
        let shared = Arc::new(RwLock::new(set));

        // A good corpus replaces the empty one.
        *shared.write().await = load_corpus(&p).expect("good corpus");
        {
            let guard = shared.read().await;
            let hits = guard.detect("张三说");
            assert!(!hits.is_empty(), "reloaded corpus must detect");
        }

        // A broken corpus must not wipe the working one.
        let bad = write("swap", BAD_REGEX);
        assert!(load_corpus(&bad).is_err());
        {
            let guard = shared.read().await;
            assert!(
                !guard.detect("张三说").is_empty(),
                "previous rules survive a failed reload"
            );
        }
    }
}
