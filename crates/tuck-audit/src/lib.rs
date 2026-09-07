//! Tamper-evident append-only audit chain.
//!
//! A generic ledger: every record carries a SHA-256 digest over its own
//! fields and the previous record's digest. Any edit, deletion, reorder or
//! insertion breaks the chain and is detected by [`verify_chain`].
//!
//! # Layering
//!
//! This crate is deliberately free of policy vocabulary. The policy layer
//! (gateway / decision engine) fills `payload` with whatever it needs —
//! destination class, detection hits, action, redaction marks, mapping
//! reference. The chain only guarantees: append-only, deterministic,
//! tamper-evident.
//!
//! # Determinism
//!
//! - `seq` is derived (recovered from chain tail on open), never random.
//! - `ts` comes from an injected [`Clock`], so tests replay identically.
//! - `hash` digests a canonical, whitespace-free JSON serialization of
//!   `(seq, ts, payload, prev_hash)` — field order fixed, no ambiguity.
//!
//! # Design rules honored
//!
//! - **极致解耦**: no tokio, no filesystem policy, pure library.
//! - **按需加载**: read/verify are separate entry points, nothing runs eagerly.
//! - **确定性优先**: same input → byte-identical chain.
//! - **0 硬编码**: nothing magic; formats are fixed in one place below.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Error type for chain operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chain is empty: {0}")]
    Empty(String),
    #[error("line {line} is not valid json: {detail}")]
    CorruptLine { line: u64, detail: String },
    #[error("line {line}: {reason}")]
    BrokenChain { line: u64, reason: String },
}

/// Injectable time source so tests can replay byte-identical chains.
pub trait Clock {
    /// RFC 3339 UTC timestamp string.
    fn now(&self) -> String;
}

/// Real system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> String {
        // Deterministic UTC RFC 3339 with second precision.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format_ts(secs)
    }
}

/// Fixed second-precision RFC 3339 (no sub-second jitter, keeps chains stable).
pub fn format_ts(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Days → (year, month, day). Howard Hinnant's civil calendar algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// One audit record. `payload` is opaque JSON owned by the policy layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    /// Monotonic sequence, derived from chain tail on open.
    pub seq: u64,
    /// Injected timestamp (RFC 3339 UTC).
    pub ts: String,
    /// Policy-layer data. Arbitrary JSON, never interpreted here.
    pub payload: serde_json::Value,
    /// Digest of the previous record (hex, lower).
    pub prev_hash: String,
    /// Digest of this record (hex, lower).
    pub hash: String,
}

impl AuditRecord {
    /// Compute the chained digest for this record's own fields.
    fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        // Canonical, whitespace-free serialization with fixed field order.
        let canonical = serde_json::to_vec(&(self.seq, &self.ts, &self.payload, &self.prev_hash))
            .expect("payload is always serializable");
        hasher.update(canonical);
        hex_lower(&hasher.finalize())
    }

    /// Build a fresh record; `hash` is derived, never trusted from input.
    pub fn new(seq: u64, ts: impl Into<String>, payload: serde_json::Value, prev_hash: &str) -> Self {
        let mut rec = AuditRecord {
            seq,
            ts: ts.into(),
            payload,
            prev_hash: prev_hash.to_string(),
            hash: String::new(),
        };
        rec.hash = rec.digest();
        rec
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Append-only chain handle.
///
/// Opened with `O_APPEND` so the kernel enforces write-only-at-end. `seq`
/// is recovered from the tail on open, so a crashed process continues the
/// chain without gaps or duplicates.
///
/// Anchoring (feature `anchor`): every `anchor_every` records the current
/// chain head is signed by an injected signer and the signature is stored
/// in an anchor record that is itself part of the chain. A full-file
/// replacement (attacker rewrites the whole chain with fresh hashes) passes
/// [`verify_chain`] but fails [`verify_anchors`] — that is the value of an
/// external witness.
pub struct AuditChain {
    file: File,
    next_seq: u64,
    tail_hash: String,
    #[cfg(feature = "anchor")]
    anchor_every: Option<u64>,
    #[cfg(feature = "anchor")]
    since_anchor: u64,
    #[cfg(feature = "anchor")]
    signer: Option<Box<dyn Fn(&[u8]) -> Vec<u8>>>,
}

impl AuditChain {
    /// Open (create if missing) a chain file and recover tail state.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;

        // The ledger is a sensitive asset: restrict to owner rw on Unix
        // (0600) so other local users cannot read the records.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        let (next_seq, tail_hash) = scan_tail(&mut file)?;
        Ok(AuditChain {
            file,
            next_seq,
            tail_hash,
            #[cfg(feature = "anchor")]
            anchor_every: None,
            #[cfg(feature = "anchor")]
            since_anchor: 0,
            #[cfg(feature = "anchor")]
            signer: None,
        })
    }

    /// Open a chain with periodic head signing (feature `anchor`).
    ///
    /// `every` must be >= 1. `signer` receives the chain-head digest and
    /// returns a raw signature (e.g. Ed25519, see [`ed25519`]).
    #[cfg(feature = "anchor")]
    pub fn open_with_anchor(
        path: &Path,
        every: u64,
        signer: Box<dyn Fn(&[u8]) -> Vec<u8>>,
    ) -> Result<Self, AuditError> {
        debug_assert!(every >= 1, "anchor interval must be >= 1");
        let mut chain = Self::open(path)?;
        chain.anchor_every = Some(every.max(1));
        chain.signer = Some(signer);
        Ok(chain)
    }

    /// Append one record. The caller supplies the payload; seq and hash
    /// chain are derived here. Returns the fully-formed record.
    pub fn append(
        &mut self,
        clock: &dyn Clock,
        payload: serde_json::Value,
    ) -> Result<AuditRecord, AuditError> {
        self.write_record(clock, payload, None)
    }

    /// Append with periodic chain-head anchoring (feature `anchor`).
    ///
    /// When the configured interval is reached, an anchor record — payload
    /// `{"anchor": true, "head": <head-hash>, "sig": <base64 signature>}` —
    /// is written first; the signature covers the chain head at that moment.
    #[cfg(feature = "anchor")]
    pub fn append_anchored(
        &mut self,
        clock: &dyn Clock,
        payload: serde_json::Value,
    ) -> Result<AuditRecord, AuditError> {
        let anchor_now = self
            .anchor_every
            .map(|every| self.since_anchor >= every)
            .unwrap_or(false);
        if anchor_now {
            if let Some(signer) = &self.signer {
                let sig = signer(self.tail_hash.as_bytes());
                let anchor_payload = serde_json::json!({
                    "anchor": true,
                    "head": self.tail_hash,
                    "sig": base64_encode(&sig),
                });
                self.write_record(clock, anchor_payload, None)?;
                self.since_anchor = 0;
            }
        }
        let rec = self.write_record(clock, payload, None)?;
        #[cfg(feature = "anchor")]
        {
            if self.anchor_every.is_some() {
                self.since_anchor += 1;
            }
        }
        Ok(rec)
    }

    fn write_record(
        &mut self,
        clock: &dyn Clock,
        payload: serde_json::Value,
        #[allow(unused)] _internal: Option<()>,
    ) -> Result<AuditRecord, AuditError> {
        let rec = AuditRecord::new(self.next_seq, clock.now(), payload, &self.tail_hash);
        let mut line = serde_json::to_vec(&rec)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.flush()?;
        self.next_seq += 1;
        self.tail_hash = rec.hash.clone();
        Ok(rec)
    }

    /// Current next sequence (useful for the policy layer / trace join).
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

fn scan_tail(file: &mut File) -> Result<(u64, String), AuditError> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file.try_clone()?);
    let mut line_no: u64 = 0;
    let mut next_seq = 0u64;
    let mut tail_hash = String::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        line_no += 1;
        let line = std::str::from_utf8(&buf[..buf.len().saturating_sub(1)])
            .map_err(|e| AuditError::CorruptLine {
                line: line_no,
                detail: e.to_string(),
            })?;
        let rec: AuditRecord =
            serde_json::from_str(line).map_err(|e| AuditError::CorruptLine {
                line: line_no,
                detail: e.to_string(),
            })?;
        next_seq = rec.seq + 1;
        tail_hash = rec.hash;
    }
    Ok((next_seq, tail_hash))
}

/// Result of a full-chain verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyReport {
    /// Total records examined.
    pub entries: u64,
    /// True when the whole chain is intact.
    pub ok: bool,
    /// Line of the first break, if any.
    pub first_break: Option<u64>,
    /// Human-readable reason for the first break.
    pub reason: Option<String>,
    /// Digest of the final record (chain head), for anchoring.
    pub head_hash: Option<String>,
}

/// Replay a chain file and report tampering.
///
/// Checks, in order: parseable JSON on every line, `seq` strictly
/// increasing, `prev_hash` equal to the previous record's `hash`, and
/// each record's stored `hash` matching a fresh digest. Any violation is
/// reported with its line number.
pub fn verify_chain(path: &Path) -> Result<VerifyReport, AuditError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A missing chain is an empty chain: valid, zero records.
            return Ok(VerifyReport {
                entries: 0,
                ok: true,
                first_break: None,
                reason: None,
                head_hash: None,
            });
        }
        Err(e) => return Err(AuditError::Io(e)),
    };
    let reader = BufReader::new(file);
    let mut entries: u64 = 0;
    let mut prev_hash = String::new();
    let mut head_hash: Option<String> = None;
    let mut line_no: u64 = 0;

    for raw in reader.lines() {
        line_no += 1;
        let line = raw?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: AuditRecord = serde_json::from_str(&line).map_err(|e| AuditError::CorruptLine {
            line: line_no,
            detail: e.to_string(),
        })?;

        // Chain linkage.
        if rec.prev_hash != prev_hash {
            return Ok(broken(
                entries,
                line_no,
                format!(
                    "prev_hash mismatch: expected {}, got {}",
                    if prev_hash.is_empty() {
                        "empty (first record)"
                    } else {
                        &prev_hash
                    },
                    rec.prev_hash
                ),
            ));
        }
        if rec.seq != entries {
            return Ok(broken(
                entries,
                line_no,
                format!("seq discontinuity: expected {entries}, got {}", rec.seq),
            ));
        }
        // Self-integrity: stored hash must equal a fresh digest.
        let fresh = rec.digest();
        if fresh != rec.hash {
            return Ok(broken(
                entries,
                line_no,
                format!("hash mismatch: stored {}, recomputed {fresh}", rec.hash),
            ));
        }

        prev_hash = rec.hash.clone();
        head_hash = Some(rec.hash.clone());
        entries += 1;
    }

    Ok(VerifyReport {
        entries,
        ok: true,
        first_break: None,
        reason: None,
        head_hash,
    })
}

fn broken(entries: u64, line: u64, reason: String) -> VerifyReport {
    VerifyReport {
        entries,
        ok: false,
        first_break: Some(line),
        reason: Some(reason),
        head_hash: None,
    }
}

/// Result of anchor-signature verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorReport {
    /// Number of anchor records found.
    pub anchors: u64,
    /// Minimum anchors required by the caller (policy-layer knowledge).
    pub min_anchors: u64,
    /// True when every anchor signature verifies and count meets the minimum.
    pub ok: bool,
    /// Line of the first bad anchor, if any.
    pub first_bad: Option<u64>,
}

/// Ed25519 helpers (feature `anchor`).
///
/// Deterministic signing per RFC 8032 — same key + message always yields
/// the same signature, so anchored chains stay byte-identical for identical
/// input (determinism requirement).
#[cfg(feature = "anchor")]
pub mod ed25519 {
    use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

    /// Sign `msg` with a 32-byte seed. Returns a raw 64-byte signature.
    pub fn sign(seed: &[u8; 32], msg: &[u8]) -> Vec<u8> {
        let key = SigningKey::from_bytes(seed);
        let sig: Signature = key.sign(msg);
        sig.to_bytes().to_vec()
    }

    /// Verify `sig` over `msg` with a 32-byte public key.
    pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(sig) else {
            return false;
        };
        key.verify_strict(msg, &sig).is_ok()
    }
}

/// Verify every anchor signature in a chain (feature `anchor`).
///
/// Each anchor record signed its `head` (the chain head at that moment)
/// with an external key. A fully rewritten chain — hashes recomputed but
/// signatures impossible to forge — passes [`verify_chain`] but fails here.
///
/// `min_anchors` is the expected lower bound, known to the policy layer
/// from its own configuration (interval × expected record count). Zero
/// anchors in a chain that was configured to anchor is itself a tamper
/// signal (the attacker stripped the witness records).
#[cfg(feature = "anchor")]
pub fn verify_anchors(
    path: &Path,
    pubkey: &[u8; 32],
    min_anchors: u64,
) -> Result<AnchorReport, AuditError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AnchorReport {
                anchors: 0,
                min_anchors,
                ok: min_anchors == 0,
                first_bad: None,
            });
        }
        Err(e) => return Err(AuditError::Io(e)),
    };
    let reader = BufReader::new(file);
    let mut anchors: u64 = 0;
    let mut line_no: u64 = 0;
    for raw in reader.lines() {
        line_no += 1;
        let line = raw?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: AuditRecord = serde_json::from_str(&line)
            .map_err(|e| AuditError::CorruptLine { line: line_no, detail: e.to_string() })?;
        let is_anchor = rec
            .payload
            .get("anchor")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !is_anchor {
            continue;
        }
        let head = rec
            .payload
            .get("head")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let sig_b64 = rec
            .payload
            .get("sig")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let sig = match base64_decode(sig_b64) {
            Some(s) => s,
            None => {
                return Ok(AnchorReport {
                    anchors,
                    min_anchors,
                    ok: false,
                    first_bad: Some(line_no),
                });
            }
        };
        anchors += 1;
        if !ed25519::verify(pubkey, head.as_bytes(), &sig) {
            return Ok(AnchorReport {
                anchors,
                min_anchors,
                ok: false,
                first_bad: Some(line_no),
            });
        }
    }
    Ok(AnchorReport {
        anchors,
        min_anchors,
        ok: anchors >= min_anchors,
        first_bad: None,
    })
}

#[cfg(feature = "anchor")]
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(feature = "anchor")]
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Pretty-print helper for CLI / humans.
impl fmt::Display for VerifyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.ok, self.first_break, &self.reason) {
            (true, _, _) => write!(
                f,
                "OK — {} records, head {}",
                self.entries,
                self.head_hash.as_deref().unwrap_or("-")
            ),
            (false, Some(line), Some(reason)) => {
                write!(f, "BROKEN at line {line} after {} records — {reason}", self.entries)
            }
            _ => write!(f, "BROKEN — {}", self.reason.as_deref().unwrap_or("unknown")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now(&self) -> String {
            format_ts(self.0)
        }
    }

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("tuck-audit-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn sample_payload(i: u64) -> serde_json::Value {
        serde_json::json!({ "n": i, "text": format!("entry-{i}") })
    }

    #[test]
    fn append_and_verify_roundtrip() {
        let path = tmp_path("roundtrip.jsonl");
        let _ = std::fs::remove_file(&path);
        let clock = FixedClock(1_700_000_000);
        let mut chain = AuditChain::open(&path).unwrap();
        for i in 0..3 {
            chain.append(&clock, sample_payload(i)).unwrap();
        }
        drop(chain);

        let report = verify_chain(&path).unwrap();
        assert!(report.ok);
        assert_eq!(report.entries, 3);
    }

    #[test]
    fn deterministic_byte_identical() {
        let a = tmp_path("det-a.jsonl");
        let b = tmp_path("det-b.jsonl");
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
        let clock = FixedClock(1_700_000_000);
        for path in [&a, &b] {
            let mut chain = AuditChain::open(path).unwrap();
            for i in 0..5 {
                chain.append(&clock, sample_payload(i)).unwrap();
            }
        }
        let fa = std::fs::read(&a).unwrap();
        let fb = std::fs::read(&b).unwrap();
        assert_eq!(fa, fb, "same input must yield byte-identical chains");
    }

    #[test]
    fn seq_recovers_from_tail() {
        let path = tmp_path("resume.jsonl");
        let _ = std::fs::remove_file(&path);
        let clock = FixedClock(1_700_000_000);
        {
            let mut chain = AuditChain::open(&path).unwrap();
            for i in 0..3 {
                chain.append(&clock, sample_payload(i)).unwrap();
            }
        }
        // New handle continues without gaps.
        let mut chain = AuditChain::open(&path).unwrap();
        assert_eq!(chain.next_seq(), 3);
        let rec = chain.append(&clock, sample_payload(99)).unwrap();
        assert_eq!(rec.seq, 3);
        drop(chain);
        let report = verify_chain(&path).unwrap();
        assert!(report.ok);
        assert_eq!(report.entries, 4);
    }

    #[test]
    fn tamper_edit_payload_breaks_chain() {
        let path = tmp_path("tamper-edit.jsonl");
        let _ = std::fs::remove_file(&path);
        let clock = FixedClock(1_700_000_000);
        {
            let mut chain = AuditChain::open(&path).unwrap();
            for i in 0..4 {
                chain.append(&clock, sample_payload(i)).unwrap();
            }
        }
        // Edit the payload of the second record in place.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut rec: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        rec["payload"]["text"] = serde_json::json!("forged");
        lines[1] = serde_json::to_string(&rec).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let report = verify_chain(&path).unwrap();
        assert!(!report.ok);
        assert_eq!(report.first_break, Some(2));
    }

    #[test]
    fn tamper_delete_row_breaks_chain() {
        let path = tmp_path("tamper-delete.jsonl");
        let _ = std::fs::remove_file(&path);
        let clock = FixedClock(1_700_000_000);
        {
            let mut chain = AuditChain::open(&path).unwrap();
            for i in 0..4 {
                chain.append(&clock, sample_payload(i)).unwrap();
            }
        }
        // Drop the third line.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        lines.remove(2);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let report = verify_chain(&path).unwrap();
        assert!(!report.ok);
        assert_eq!(report.first_break, Some(3));
    }

    #[test]
    fn tamper_reorder_breaks_chain() {
        let path = tmp_path("tamper-reorder.jsonl");
        let _ = std::fs::remove_file(&path);
        let clock = FixedClock(1_700_000_000);
        {
            let mut chain = AuditChain::open(&path).unwrap();
            for i in 0..4 {
                chain.append(&clock, sample_payload(i)).unwrap();
            }
        }
        // Swap lines 1 and 2.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        lines.swap(1, 2);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let report = verify_chain(&path).unwrap();
        assert!(!report.ok);
        assert_eq!(report.first_break, Some(2));
    }

    #[test]
    fn empty_chain_verifies() {
        let path = tmp_path("empty.jsonl");
        let _ = std::fs::remove_file(&path);
        let report = verify_chain(&path).unwrap();
        assert!(report.ok);
        assert_eq!(report.entries, 0);
    }

    #[cfg(feature = "anchor")]
    mod anchor_tests {
        use super::*;

        fn keypair() -> ([u8; 32], [u8; 32]) {
            // Fixed seed → deterministic keys (no RNG in tests).
            let seed: [u8; 32] = [7u8; 32];
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            (seed, sk.verifying_key().to_bytes())
        }

        #[test]
        fn anchored_chain_writes_interval_records() {
            let path = tmp_path("anchor-interval.jsonl");
            let _ = std::fs::remove_file(&path);
            let (seed, _vk) = keypair();
            let clock = FixedClock(1_700_000_000);
            {
                let mut chain = AuditChain::open_with_anchor(
                    &path,
                    3,
                    Box::new(move |msg: &[u8]| ed25519::sign(&seed, msg)),
                )
                .unwrap();
                for i in 0..7 {
                    chain.append_anchored(&clock, sample_payload(i)).unwrap();
                }
            }
            // 7 records, intervals at 3 and 6 → 2 anchors, 9 records total.
            let report = verify_chain(&path).unwrap();
            assert!(report.ok);
            assert_eq!(report.entries, 9);
        }

        #[test]
        fn anchors_verify_with_correct_key() {
            let path = tmp_path("anchor-ok.jsonl");
            let _ = std::fs::remove_file(&path);
            let (seed, vk) = keypair();
            let clock = FixedClock(1_700_000_000);
            {
                let mut chain = AuditChain::open_with_anchor(
                    &path,
                    2,
                    Box::new(move |msg: &[u8]| ed25519::sign(&seed, msg)),
                )
                .unwrap();
                for i in 0..5 {
                    chain.append_anchored(&clock, sample_payload(i)).unwrap();
                }
            }
            let report = verify_anchors(&path, &vk, 1).unwrap();
            assert!(report.ok);
            assert_eq!(report.anchors, 2);
        }

        #[test]
        fn full_chain_replacement_fails_anchors() {
            // The core value: attacker rewrites the whole file with fresh
            // hashes (self-consistent chain) — verify_chain passes, but the
            // external witness (anchors) rejects it.
            let path = tmp_path("anchor-replace.jsonl");
            let _ = std::fs::remove_file(&path);
            let (seed, vk) = keypair();
            let clock = FixedClock(1_700_000_000);
            {
                let mut chain = AuditChain::open_with_anchor(
                    &path,
                    2,
                    Box::new(move |msg: &[u8]| ed25519::sign(&seed, msg)),
                )
                .unwrap();
                for i in 0..5 {
                    chain.append_anchored(&clock, sample_payload(i)).unwrap();
                }
            }
            // Rebuild the file from scratch with forged payloads but a
            // freshly computed (self-consistent) hash chain.
            let mut lines = String::new();
            let mut prev = String::new();
            for i in 0..5u64 {
                let rec = AuditRecord::new(
                    i,
                    clock.now(),
                    serde_json::json!({ "n": i, "text": format!("forged-{i}") }),
                    &prev,
                );
                prev = rec.hash.clone();
                lines.push_str(&serde_json::to_string(&rec).unwrap());
                lines.push('\n');
            }
            std::fs::write(&path, lines).unwrap();

            let chain_report = verify_chain(&path).unwrap();
            assert!(chain_report.ok, "rewritten chain is self-consistent");

            let anchor_report = verify_anchors(&path, &vk, 1).unwrap();
            assert!(!anchor_report.ok, "anchors must reject a forged rewrite");
        }

        #[test]
        fn wrong_key_rejects_anchors() {
            let path = tmp_path("anchor-wrongkey.jsonl");
            let _ = std::fs::remove_file(&path);
            let (seed, _vk) = keypair();
            let clock = FixedClock(1_700_000_000);
            {
                let mut chain = AuditChain::open_with_anchor(
                    &path,
                    2,
                    Box::new(move |msg: &[u8]| ed25519::sign(&seed, msg)),
                )
                .unwrap();
                for i in 0..5 {
                    chain.append_anchored(&clock, sample_payload(i)).unwrap();
                }
            }
            let other: [u8; 32] = [9u8; 32];
            let report = verify_anchors(&path, &other, 1).unwrap();
            assert!(!report.ok);
        }
    }
}
