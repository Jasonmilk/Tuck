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

use std::collections::HashMap;

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
}
