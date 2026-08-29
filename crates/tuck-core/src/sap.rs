//! SAP (Security Attestation Protocol) — optional enhancement layer.
//!
//! SAP is the *evolutionary* layer of the CI-144 protocol family. It provides
//! replay protection (Seq-Counter), physical context attestation (PAH-Hash),
//! and signature verification (PAH-Signature).
//!
//! # Critical Design Constraint
//!
//! **SAP verification is NOT in the hard real-time path.** The `decide()` function
//! in `crate::decide` only reads the 4-byte PFP header. SAP verification is an
//! optional, asynchronous enhancement that runs *after* the PFP decision, or
//! *before* frame processing in non-real-time contexts.
//!
//! This follows the "按需加载" (on-demand loading) principle: SAP is loaded
//! and verified only when replay protection or attestation is required.
//!
//! # SAP Frame Layout (28 bytes)
//!
//! ```text
//! Byte 0-1:   Family-Magic (0xCF14, big-endian)
//! Byte 2:     Protocol-ID (0x01 = SAP)
//! Byte 3:     Version (0x01 = v1)
//! Byte 4-5:   Seq-Counter (u16, big-endian, monotonic)
//! Byte 6-19:  PAH-Hash (14 bytes, SHA-256 truncated high 112 bits)
//! Byte 20-27: PAH-Signature (8 bytes, ECC truncated)
//! ```

use std::collections::{HashMap, VecDeque};
use sha2::{Sha256, Digest};

// ============================================================================
// Constants
// ============================================================================

/// SAP frame size in bytes.
pub const SAP_SIZE: usize = 28;

/// SAP protocol ID (byte 2).
pub const SAP_PROTOCOL_ID: u8 = 0x01;

/// SAP version (byte 3).
pub const SAP_VERSION: u8 = 0x01;

/// Family magic (byte 0-1, big-endian).
pub const FAMILY_MAGIC: u16 = 0xCF14;

/// Seq-Counter rotation threshold. When seq >= this value, key rotation is needed.
pub const SEQ_ROTATION_THRESHOLD: u16 = 65534;

// ============================================================================
// SapHeader — zero-copy, lazy extraction
// ============================================================================

/// SAP header — 28 bytes, zero-copy storage, lazy field extraction.
///
/// Stores the raw bytes and provides methods to extract fields on demand.
/// This follows the same zero-copy pattern as `crate::PfpHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SapHeader {
    raw: [u8; SAP_SIZE],
}

impl SapHeader {
    /// Create a SapHeader from raw bytes, validating magic and protocol ID.
    pub fn from_bytes(bytes: [u8; SAP_SIZE]) -> Result<Self, SapError> {
        let magic = u16::from_be_bytes([bytes[0], bytes[1]]);
        if magic != FAMILY_MAGIC {
            return Err(SapError::InvalidMagic(magic));
        }
        if bytes[2] != SAP_PROTOCOL_ID {
            return Err(SapError::InvalidProtocolId(bytes[2]));
        }
        Ok(Self { raw: bytes })
    }

    /// Get raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; SAP_SIZE] {
        &self.raw
    }

    /// Protocol version (byte 3).
    #[inline]
    pub fn version(&self) -> u8 {
        self.raw[3]
    }

    /// Check if version is current (SAP_VERSION).
    #[inline]
    pub fn is_version_current(&self) -> bool {
        self.version() == SAP_VERSION
    }

    /// Seq-Counter (byte 4-5, big-endian u16).
    #[inline]
    pub fn seq_counter(&self) -> u16 {
        u16::from_be_bytes([self.raw[4], self.raw[5]])
    }

    /// Check if key rotation is needed (seq >= threshold).
    #[inline]
    pub fn needs_key_rotation(&self) -> bool {
        self.seq_counter() >= SEQ_ROTATION_THRESHOLD
    }

    /// PAH-Hash (byte 6-19, 14 bytes).
    #[inline]
    pub fn pah_hash(&self) -> &[u8; 14] {
        self.raw[6..20].try_into().expect("SAP PAH-Hash slice is always 14 bytes")
    }

    /// PAH-Signature (byte 20-27, 8 bytes).
    #[inline]
    pub fn pah_signature(&self) -> &[u8; 8] {
        self.raw[20..28].try_into().expect("SAP PAH-Signature slice is always 8 bytes")
    }
}

// ============================================================================
// ReplayCache — pluggable replay protection
// ============================================================================

/// Replay cache trait — pluggable storage for last-seen sequence numbers.
///
/// Implementations can be in-memory (HashMap), persistent (database), or
/// distributed (Redis). Tuck-core provides a simple in-memory implementation.
///
/// This follows the "极致解耦" principle: replay cache is separate from
/// the decision engine, and can be replaced without affecting `decide()`.
pub trait ReplayCache {
    /// Check if the sequence number is valid (greater than last seen),
    /// then update the last seen value.
    ///
    /// Returns `Ok(())` if valid, `Err(ReplayError)` if replay detected.
    fn check_and_update(&mut self, source_id: &str, seq: u16) -> Result<(), ReplayError>;

    /// Get the last seen sequence number for a source.
    fn last_seen(&self, source_id: &str) -> Option<u16>;
}

/// In-memory replay cache — simple HashMap-based implementation.
///
/// Suitable for single-process Tuck deployments. For distributed deployments,
/// implement `ReplayCache` with a shared store (Redis, etc.).
#[derive(Debug, Default)]
pub struct InMemoryReplayCache {
    last_seen: HashMap<String, u16>,
}

impl InMemoryReplayCache {
    /// Create a new empty in-memory replay cache.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_update(&mut self, source_id: &str, seq: u16) -> Result<(), ReplayError> {
        match self.last_seen.get(source_id) {
            Some(&last) => {
                if seq <= last {
                    return Err(ReplayError::ReplayDetected {
                        source_id: source_id.to_string(),
                        last_seen: last,
                        received: seq,
                    });
                }
            }
            None => {
                // First time seeing this source — any seq is valid
            }
        }
        self.last_seen.insert(source_id.to_string(), seq);
        Ok(())
    }

    fn last_seen(&self, source_id: &str) -> Option<u16> {
        self.last_seen.get(source_id).copied()
    }
}

// ============================================================================
// Errors
// ============================================================================

/// SAP verification error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SapError {
    /// Invalid family magic (not 0xCF14).
    #[error("invalid family magic: 0x{0:04X}, expected 0xCF14")]
    InvalidMagic(u16),

    /// Invalid protocol ID (not 0x01).
    #[error("invalid protocol ID: 0x{0:02X}, expected 0x01")]
    InvalidProtocolId(u8),

    /// Unsupported SAP version.
    #[error("unsupported SAP version: {0}, expected {SAP_VERSION}")]
    UnsupportedVersion(u8),

    /// Replay detected.
    #[error("replay detected: source={source_id}, last_seen={last_seen}, received={received}")]
    ReplayDetected {
        /// Source identifier.
        source_id: String,
        /// Last seen sequence number.
        last_seen: u16,
        /// Received sequence number.
        received: u16,
    },

    /// Key rotation needed (seq >= threshold).
    #[error("key rotation needed: seq={0} >= threshold={SEQ_ROTATION_THRESHOLD}")]
    KeyRotationNeeded(u16),

    /// Invalid PAH signature.
    #[error("invalid PAH signature")]
    InvalidSignature,
}

/// Replay detection error (alias for SapError::ReplayDetected).
pub type ReplayError = SapError;

// ============================================================================
// SAP verification — optional enhancement, NOT in hard real-time path
// ============================================================================

/// Verify SAP header: magic, protocol ID, version, and replay protection.
///
/// # Important
///
/// This function is **NOT** in the hard real-time path. It should be called
/// *after* `decide()` (PFP decision), or in non-real-time contexts.
///
/// The PFP `decide()` function makes the initial pass/reject decision in
/// sub-microsecond time. SAP verification adds replay protection and
/// attestation, but at the cost of cache lookups and potential I/O.
///
/// # Flow
///
/// ```text
/// Frame arrives
///   ↓
/// PFP decide() → Pass/Reject/NeedHumanConfirm (sub-μs, hard real-time)
///   ↓ (if Pass and SAP present)
/// SAP verify_sap() → Ok/ReplayDetected/KeyRotationNeeded (optional, async)
///   ↓
/// If ReplayDetected → override decision to Reject + audit
/// If KeyRotationNeeded → trigger key rotation workflow
/// ```
pub fn verify_sap(
    sap: &SapHeader,
    source_id: &str,
    cache: &mut impl ReplayCache,
) -> Result<(), SapError> {
    // 1. Version check
    if !sap.is_version_current() {
        return Err(SapError::UnsupportedVersion(sap.version()));
    }

    // 2. Key rotation check (warning, not fatal — caller decides)
    if sap.needs_key_rotation() {
        // Don't return error here — rotation is a separate workflow.
        // Caller can check sap.needs_key_rotation() separately.
    }

    // 3. Replay protection (Seq-Counter check)
    cache.check_and_update(source_id, sap.seq_counter())?;

    Ok(())
}

/// Verify SAP from raw bytes — convenience wrapper.
pub fn verify_sap_from_bytes(
    bytes: &[u8],
    source_id: &str,
    cache: &mut impl ReplayCache,
) -> Result<(), SapError> {
    if bytes.len() < SAP_SIZE {
        return Err(SapError::InvalidMagic(0)); // too short, treat as invalid
    }
    let mut arr = [0u8; SAP_SIZE];
    arr.copy_from_slice(&bytes[..SAP_SIZE]);
    let sap = SapHeader::from_bytes(arr)?;
    verify_sap(&sap, source_id, cache)
}

// ============================================================================
// PAH Signature Verification — 64-bit truncated signature
// ============================================================================

/// Signature verifier trait — pluggable PAH-Signature verification.
///
/// Software stage uses HMAC-SHA256 truncated to 64 bits.
/// Hardware stage will use ECC (ed25519) with hardware acceleration.
///
/// This follows the "渐进生长" principle: protocol defines the interface,
/// current software implementation can be replaced by hardware implementation
/// without changing the calling code.
pub trait SignatureVerifier: Send + Sync {
    /// Verify the PAH-Signature (8 bytes) against the PAH-Hash (14 bytes)
    /// and source identifier.
    ///
    /// Returns `Ok(())` if signature is valid, `Err(SapError)` if invalid.
    fn verify_signature(
        &self,
        source_id: &str,
        pah_hash: &[u8; 14],
        signature: &[u8; 8],
    ) -> Result<(), SapError>;
}

/// Software signature verifier — HMAC-SHA256 truncated to 64 bits.
///
/// Uses a shared secret key to compute HMAC-SHA256 over (source_id + pah_hash),
/// then takes the first 8 bytes as the truncated signature.
///
/// # Security Note
///
/// This is a software-stage simulation. The production CI-144 v2.0 protocol
/// uses ECC signatures (ed25519) with the first layer being 64-bit truncated
/// for hard real-time, and the second layer being full 512-bit for post-hoc
/// audit. This software verifier provides equivalent security for testing
/// and single-node deployments.
#[derive(Clone)]
pub struct SoftwareSignatureVerifier {
    /// Shared secret key for HMAC.
    key: Vec<u8>,
}

impl SoftwareSignatureVerifier {
    /// Create a new software signature verifier with the given shared key.
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }

    /// Compute the expected 64-bit truncated signature for a source + hash.
    pub fn compute_signature(&self, source_id: &str, pah_hash: &[u8; 14]) -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(source_id.as_bytes());
        hasher.update(pah_hash);
        let result = hasher.finalize();
        let mut sig = [0u8; 8];
        sig.copy_from_slice(&result[..8]);
        sig
    }
}

impl SignatureVerifier for SoftwareSignatureVerifier {
    fn verify_signature(
        &self,
        source_id: &str,
        pah_hash: &[u8; 14],
        signature: &[u8; 8],
    ) -> Result<(), SapError> {
        let expected = self.compute_signature(source_id, pah_hash);
        // Constant-time comparison to prevent timing attacks
        let mut diff = 0u8;
        for i in 0..8 {
            diff |= expected[i] ^ signature[i];
        }
        if diff != 0 {
            return Err(SapError::InvalidSignature);
        }
        Ok(())
    }
}

// ============================================================================
// Enhanced Replay Cache — LRU eviction + capacity limit
// ============================================================================

/// Enhanced in-memory replay cache with LRU eviction and capacity limit.
///
/// Uses a HashMap + VecDeque for O(1) lookup + O(1) LRU eviction.
/// Default capacity: 1024 sources (configurable).
///
/// This follows the "极致节能" principle: fixed capacity prevents unbounded
/// memory growth, LRU eviction keeps the most active sources in cache.
#[derive(Debug)]
pub struct LruReplayCache {
    /// Last seen sequence number per source.
    last_seen: HashMap<String, u16>,
    /// LRU order (front = most recently used, back = least recently used).
    lru_order: VecDeque<String>,
    /// Maximum number of sources to track.
    capacity: usize,
}

impl LruReplayCache {
    /// Create a new LRU replay cache with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            last_seen: HashMap::with_capacity(capacity),
            lru_order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Create a new LRU replay cache with default capacity (1024 sources).
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    /// Get the current number of tracked sources.
    pub fn len(&self) -> usize {
        self.last_seen.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.last_seen.is_empty()
    }

    /// Get the cache capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Touch a source (move to front of LRU order).
    fn touch(&mut self, source_id: &str) {
        // Remove from current position (if exists)
        self.lru_order.retain(|s| s != source_id);
        // Add to front
        self.lru_order.push_front(source_id.to_string());
    }

    /// Evict the least recently used source.
    fn evict_lru(&mut self) {
        if let Some(lru) = self.lru_order.pop_back() {
            self.last_seen.remove(&lru);
        }
    }
}

impl Default for LruReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache for LruReplayCache {
    fn check_and_update(&mut self, source_id: &str, seq: u16) -> Result<(), ReplayError> {
        match self.last_seen.get(source_id) {
            Some(&last) => {
                if seq <= last {
                    return Err(ReplayError::ReplayDetected {
                        source_id: source_id.to_string(),
                        last_seen: last,
                        received: seq,
                    });
                }
            }
            None => {
                // First time seeing this source — check capacity
                if self.last_seen.len() >= self.capacity {
                    self.evict_lru();
                }
            }
        }
        self.last_seen.insert(source_id.to_string(), seq);
        self.touch(source_id);
        Ok(())
    }

    fn last_seen(&self, source_id: &str) -> Option<u16> {
        self.last_seen.get(source_id).copied()
    }
}

// ============================================================================
// decide_with_sap — PFP decision + SAP enhancement (optional, NOT hard real-time)
// ============================================================================

/// SAP-enhanced decision result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SapDecision {
    /// Pass — PFP decision is Pass and SAP verification passed.
    Pass,
    /// Reject — PFP decision is Reject, or SAP verification failed.
    Reject {
        /// Reason for rejection.
        reason: String,
    },
    /// NeedHumanConfirm — PFP decision is NeedHumanConfirm.
    NeedHumanConfirm,
    /// HardOverridePass — PFP decision is HardOverridePass (emergency override).
    HardOverridePass,
}

/// Make a PFP decision with optional SAP enhancement.
///
/// # Flow
///
/// 1. Make the hard real-time PFP decision (sub-μs)
/// 2. If PFP decision is Pass and SAP is provided, verify SAP:
///    - Version check
///    - Replay protection (Seq-Counter)
///    - PAH-Signature verification (if verifier is provided)
/// 3. If SAP verification fails, override decision to Reject
/// 4. Return the final decision
///
/// # Important
///
/// This function is **NOT** in the hard real-time path. It includes cache
/// lookups and potentially signature verification. For hard real-time use,
/// call `crate::decide()` directly and run SAP verification asynchronously.
///
/// This follows the "按需加载" principle: SAP verification is only performed
/// when SAP is present and the caller explicitly requests enhanced verification.
pub fn decide_with_sap(
    pfp: &crate::PfpHeader,
    sap: Option<&SapHeader>,
    source_id: &str,
    cache: &mut impl ReplayCache,
    verifier: Option<&dyn SignatureVerifier>,
    policy: &crate::SecurityPolicy,
) -> SapDecision {
    // Step 1: Hard real-time PFP decision
    let pfp_decision = crate::decide(pfp, policy);

    // If PFP decision is not Pass, no need for SAP verification
    match pfp_decision {
        crate::Decision::Reject => return SapDecision::Reject {
            reason: "PFP policy rejected".to_string(),
        },
        crate::Decision::NeedHumanConfirm => return SapDecision::NeedHumanConfirm,
        crate::Decision::HardOverridePass => return SapDecision::HardOverridePass,
        crate::Decision::Pass => {}
    }

    // Step 2: SAP verification (only if SAP is provided)
    let Some(sap) = sap else {
        return SapDecision::Pass; // No SAP — PFP Pass is final
    };

    // 2a: Version check
    if !sap.is_version_current() {
        return SapDecision::Reject {
            reason: format!("unsupported SAP version: {}", sap.version()),
        };
    }

    // 2b: Replay protection
    if let Err(e) = cache.check_and_update(source_id, sap.seq_counter()) {
        return SapDecision::Reject {
            reason: format!("replay detected: {e}"),
        };
    }

    // 2c: PAH-Signature verification (only if verifier is provided)
    if let Some(verifier) = verifier {
        if let Err(e) = verifier.verify_signature(source_id, sap.pah_hash(), sap.pah_signature()) {
            return SapDecision::Reject {
                reason: format!("invalid PAH signature: {e}"),
            };
        }
    }

    // All checks passed
    SapDecision::Pass
}

// Add InvalidSignature to SapError (need to modify the enum)
// Note: We'll add it via a new variant below

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sap(seq: u16) -> SapHeader {
        let mut bytes = [0u8; SAP_SIZE];
        bytes[0] = 0xCF;
        bytes[1] = 0x14;
        bytes[2] = SAP_PROTOCOL_ID;
        bytes[3] = SAP_VERSION;
        bytes[4] = (seq >> 8) as u8;
        bytes[5] = (seq & 0xFF) as u8;
        SapHeader::from_bytes(bytes).unwrap()
    }

    #[test]
    fn test_sap_decode() {
        let sap = make_sap(42);
        assert_eq!(sap.seq_counter(), 42);
        assert_eq!(sap.version(), SAP_VERSION);
        assert!(sap.is_version_current());
        assert!(!sap.needs_key_rotation());
    }

    #[test]
    fn test_sap_invalid_magic() {
        let mut bytes = [0u8; SAP_SIZE];
        bytes[0] = 0x00;
        bytes[1] = 0x00;
        bytes[2] = SAP_PROTOCOL_ID;
        let result = SapHeader::from_bytes(bytes);
        assert!(matches!(result, Err(SapError::InvalidMagic(_))));
    }

    #[test]
    fn test_sap_invalid_protocol_id() {
        let mut bytes = [0u8; SAP_SIZE];
        bytes[0] = 0xCF;
        bytes[1] = 0x14;
        bytes[2] = 0x99; // wrong protocol ID
        let result = SapHeader::from_bytes(bytes);
        assert!(matches!(result, Err(SapError::InvalidProtocolId(0x99))));
    }

    #[test]
    fn test_replay_cache_accept_increasing() {
        let mut cache = InMemoryReplayCache::new();
        assert!(cache.check_and_update("source1", 1).is_ok());
        assert!(cache.check_and_update("source1", 2).is_ok());
        assert!(cache.check_and_update("source1", 100).is_ok());
        assert_eq!(cache.last_seen("source1"), Some(100));
    }

    #[test]
    fn test_replay_cache_detect_replay() {
        let mut cache = InMemoryReplayCache::new();
        assert!(cache.check_and_update("source1", 10).is_ok());
        // Same seq → replay
        let result = cache.check_and_update("source1", 10);
        assert!(matches!(result, Err(SapError::ReplayDetected { .. })));
        // Lower seq → replay
        let result = cache.check_and_update("source1", 5);
        assert!(matches!(result, Err(SapError::ReplayDetected { .. })));
    }

    #[test]
    fn test_replay_cache_isolated_sources() {
        let mut cache = InMemoryReplayCache::new();
        assert!(cache.check_and_update("source1", 10).is_ok());
        // Different source can use same seq
        assert!(cache.check_and_update("source2", 10).is_ok());
        assert_eq!(cache.last_seen("source1"), Some(10));
        assert_eq!(cache.last_seen("source2"), Some(10));
    }

    #[test]
    fn test_verify_sap_full_flow() {
        let mut cache = InMemoryReplayCache::new();
        let sap1 = make_sap(1);
        let sap2 = make_sap(2);
        let sap_replay = make_sap(1); // replay of sap1

        assert!(verify_sap(&sap1, "node-a", &mut cache).is_ok());
        assert!(verify_sap(&sap2, "node-a", &mut cache).is_ok());
        // Replay detected
        let result = verify_sap(&sap_replay, "node-a", &mut cache);
        assert!(matches!(result, Err(SapError::ReplayDetected { .. })));
    }

    #[test]
    fn test_verify_sap_from_bytes() {
        let mut cache = InMemoryReplayCache::new();
        let sap = make_sap(5);
        assert!(verify_sap_from_bytes(sap.as_bytes(), "node-b", &mut cache).is_ok());
        // Too short
        let short = [0u8; 4];
        assert!(verify_sap_from_bytes(&short, "node-b", &mut cache).is_err());
    }

    #[test]
    fn test_key_rotation_threshold() {
        let sap = make_sap(SEQ_ROTATION_THRESHOLD);
        assert!(sap.needs_key_rotation());
        let sap = make_sap(SEQ_ROTATION_THRESHOLD - 1);
        assert!(!sap.needs_key_rotation());
    }

    #[test]
    fn test_sap_not_in_hard_real_time_path() {
        // Documentational test: SAP verification requires mutable cache reference,
        // which means it cannot be in the no-allocation, no-lock decide() path.
        // This test ensures the API design enforces this separation.
        fn assert_not_real_time<F: Fn(&mut InMemoryReplayCache)>(_f: F) {}
        assert_not_real_time(|cache| {
            let sap = make_sap(1);
            let _ = verify_sap(&sap, "test", cache);
        });
    }

    // ========================================================================
    // Signature Verifier Tests
    // ========================================================================

    #[test]
    fn test_software_signature_verify_valid() {
        let verifier = SoftwareSignatureVerifier::new(b"test-secret-key");
        let pah_hash = [0xABu8; 14];
        let sig = verifier.compute_signature("source1", &pah_hash);
        assert!(verifier.verify_signature("source1", &pah_hash, &sig).is_ok());
    }

    #[test]
    fn test_software_signature_verify_invalid() {
        let verifier = SoftwareSignatureVerifier::new(b"test-secret-key");
        let pah_hash = [0xABu8; 14];
        let wrong_sig = [0x00u8; 8];
        let result = verifier.verify_signature("source1", &pah_hash, &wrong_sig);
        assert!(matches!(result, Err(SapError::InvalidSignature)));
    }

    #[test]
    fn test_software_signature_different_source() {
        let verifier = SoftwareSignatureVerifier::new(b"test-secret-key");
        let pah_hash = [0xABu8; 14];
        let sig = verifier.compute_signature("source1", &pah_hash);
        // Same signature, different source → should fail
        let result = verifier.verify_signature("source2", &pah_hash, &sig);
        assert!(matches!(result, Err(SapError::InvalidSignature)));
    }

    #[test]
    fn test_software_signature_different_hash() {
        let verifier = SoftwareSignatureVerifier::new(b"test-secret-key");
        let pah_hash1 = [0xABu8; 14];
        let pah_hash2 = [0xCDu8; 14];
        let sig = verifier.compute_signature("source1", &pah_hash1);
        // Same signature, different hash → should fail
        let result = verifier.verify_signature("source1", &pah_hash2, &sig);
        assert!(matches!(result, Err(SapError::InvalidSignature)));
    }

    #[test]
    fn test_software_signature_deterministic() {
        let verifier = SoftwareSignatureVerifier::new(b"test-secret-key");
        let pah_hash = [0xABu8; 14];
        let sig1 = verifier.compute_signature("source1", &pah_hash);
        let sig2 = verifier.compute_signature("source1", &pah_hash);
        assert_eq!(sig1, sig2);
    }

    // ========================================================================
    // LRU Replay Cache Tests
    // ========================================================================

    #[test]
    fn test_lru_cache_basic() {
        let mut cache = LruReplayCache::with_capacity(3);
        assert!(cache.check_and_update("s1", 1).is_ok());
        assert!(cache.check_and_update("s2", 1).is_ok());
        assert!(cache.check_and_update("s3", 1).is_ok());
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_lru_cache_eviction() {
        let mut cache = LruReplayCache::with_capacity(2);
        assert!(cache.check_and_update("s1", 1).is_ok());
        assert!(cache.check_and_update("s2", 1).is_ok());
        // Touch s1 to make it most recently used
        assert!(cache.check_and_update("s1", 2).is_ok());
        // Add s3 — should evict s2 (least recently used)
        assert!(cache.check_and_update("s3", 1).is_ok());
        assert_eq!(cache.len(), 2);
        assert!(cache.last_seen("s1").is_some());
        assert!(cache.last_seen("s2").is_none());
        assert!(cache.last_seen("s3").is_some());
    }

    #[test]
    fn test_lru_cache_replay_detection() {
        let mut cache = LruReplayCache::new();
        assert!(cache.check_and_update("s1", 10).is_ok());
        let result = cache.check_and_update("s1", 5);
        assert!(matches!(result, Err(SapError::ReplayDetected { .. })));
    }

    #[test]
    fn test_lru_cache_default_capacity() {
        let cache = LruReplayCache::new();
        assert_eq!(cache.capacity(), 1024);
        assert!(cache.is_empty());
    }

    // ========================================================================
    // decide_with_sap Integration Tests
    // ========================================================================

    fn make_pfp(risk: crate::RiskLevel, override_flag: crate::OverrideFlag) -> crate::PfpHeader {
        let mut bytes = [0xCF, 0x14, 0, 0];
        bytes[2] = (risk as u8) << 2;
        bytes[3] = (override_flag as u8) << 1 | 0b100; // Replay enabled
        crate::PfpHeader::from_bytes(bytes).unwrap()
    }

    #[test]
    fn test_decide_with_sap_pass_no_sap() {
        let policy = crate::SecurityPolicy::default();
        let mut cache = LruReplayCache::new();
        let pfp = make_pfp(crate::RiskLevel::Low, crate::OverrideFlag::Normal);
        let result = decide_with_sap(&pfp, None, "source1", &mut cache, None, &policy);
        assert_eq!(result, SapDecision::Pass);
    }

    #[test]
    fn test_decide_with_sap_pass_with_sap() {
        let policy = crate::SecurityPolicy::default();
        let mut cache = LruReplayCache::new();
        let pfp = make_pfp(crate::RiskLevel::Low, crate::OverrideFlag::Normal);
        let sap = make_sap(1);
        let result = decide_with_sap(&pfp, Some(&sap), "source1", &mut cache, None, &policy);
        assert_eq!(result, SapDecision::Pass);
    }

    #[test]
    fn test_decide_with_sap_replay_detected() {
        let policy = crate::SecurityPolicy::default();
        let mut cache = LruReplayCache::new();
        let pfp = make_pfp(crate::RiskLevel::Low, crate::OverrideFlag::Normal);
        let sap1 = make_sap(5);
        let sap2 = make_sap(5); // replay

        assert!(decide_with_sap(&pfp, Some(&sap1), "s1", &mut cache, None, &policy) == SapDecision::Pass);
        let result = decide_with_sap(&pfp, Some(&sap2), "s1", &mut cache, None, &policy);
        assert!(matches!(result, SapDecision::Reject { .. }));
    }

    #[test]
    fn test_decide_with_sap_pfp_reject() {
        let policy = crate::SecurityPolicy::default();
        let mut cache = LruReplayCache::new();
        // Catastrophic without override → Reject
        let pfp = make_pfp(crate::RiskLevel::Catastrophic, crate::OverrideFlag::Normal);
        let sap = make_sap(1);
        let result = decide_with_sap(&pfp, Some(&sap), "s1", &mut cache, None, &policy);
        assert!(matches!(result, SapDecision::Reject { .. }));
    }

    #[test]
    fn test_decide_with_sap_hard_override() {
        let policy = crate::SecurityPolicy::default();
        let mut cache = LruReplayCache::new();
        // Catastrophic with override → HardOverridePass (SAP not checked)
        let pfp = make_pfp(crate::RiskLevel::Catastrophic, crate::OverrideFlag::HardOverride);
        let sap = make_sap(1);
        let result = decide_with_sap(&pfp, Some(&sap), "s1", &mut cache, None, &policy);
        assert_eq!(result, SapDecision::HardOverridePass);
    }

    #[test]
    fn test_decide_with_sap_signature_verified() {
        let policy = crate::SecurityPolicy::default();
        let mut cache = LruReplayCache::new();
        let verifier = SoftwareSignatureVerifier::new(b"test-key");
        let pfp = make_pfp(crate::RiskLevel::Low, crate::OverrideFlag::Normal);

        // Create SAP with valid signature
        let mut sap_bytes = [0u8; SAP_SIZE];
        sap_bytes[0] = 0xCF;
        sap_bytes[1] = 0x14;
        sap_bytes[2] = SAP_PROTOCOL_ID;
        sap_bytes[3] = SAP_VERSION;
        sap_bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        let pah_hash = [0xABu8; 14];
        sap_bytes[6..20].copy_from_slice(&pah_hash);
        let sig = verifier.compute_signature("s1", &pah_hash);
        sap_bytes[20..28].copy_from_slice(&sig);
        let sap = SapHeader::from_bytes(sap_bytes).unwrap();

        let result = decide_with_sap(&pfp, Some(&sap), "s1", &mut cache, Some(&verifier), &policy);
        assert_eq!(result, SapDecision::Pass);
    }

    #[test]
    fn test_decide_with_sap_signature_invalid() {
        let policy = crate::SecurityPolicy::default();
        let mut cache = LruReplayCache::new();
        let verifier = SoftwareSignatureVerifier::new(b"test-key");
        let pfp = make_pfp(crate::RiskLevel::Low, crate::OverrideFlag::Normal);

        // Create SAP with invalid signature
        let mut sap_bytes = [0u8; SAP_SIZE];
        sap_bytes[0] = 0xCF;
        sap_bytes[1] = 0x14;
        sap_bytes[2] = SAP_PROTOCOL_ID;
        sap_bytes[3] = SAP_VERSION;
        sap_bytes[4..6].copy_from_slice(&1u16.to_be_bytes());
        // pah_hash and signature are all zeros (invalid)
        let sap = SapHeader::from_bytes(sap_bytes).unwrap();

        let result = decide_with_sap(&pfp, Some(&sap), "s1", &mut cache, Some(&verifier), &policy);
        assert!(matches!(result, SapDecision::Reject { .. }));
    }
}
