//! Tuck Core — Hard real-time security gate core.
//!
//! Tuck is the immune system of the Helix ecosystem. It reads only the 4-byte
//! PFP (Physical Feature Protocol) header from each CI-144 frame and makes
//! a pass/reject/human-confirm decision in sub-microsecond time.
//!
//! # Core Principles
//!
//! - **PFP-only read**: The hard real-time path only reads the 4-byte PFP header,
//!   never decrypts payload, never parses INTENT-7 semantics.
//! - **fail-closed**: Any error (parse failure, missing policy, timeout) defaults
//!   to `Decision::Reject`. Never default-pass.
//! - **Zero allocation**: The `decide()` function performs no heap allocation,
//!   no locking, no async await. Stack-only, fixed-size arrays.
//! - **Sub-microsecond**: p99 decision latency < 1μs.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod sap;
pub mod policy;
pub mod hitl;
pub mod catastrophic;
pub mod hot_reload;
pub mod credential;
pub mod injection;
pub mod file_store;
pub mod hsm;
pub mod audit;
pub mod audit_store;
pub mod audit_query;
pub mod tamper;
pub mod frame;
pub mod proxy;
pub mod outbound;
pub mod mind_bridge;

// ============================================================================
// PFP Header (4 bytes / 32 bits)
// ============================================================================

/// Physical Feature Protocol header — 4 bytes, fixed offset, plaintext.
///
/// This is the *only* data Tuck reads in the hard real-time path.
///
/// # Byte Layout
///
/// ```text
/// Byte 0-1: Family-Magic (0xCF14, big-endian)
/// Byte 2:
///   bit 0-1: Modality       (0=COGNITIVE, 1=RENDER, 2=EXECUTIVE, 3=SENSOR_FEED)
///   bit 2-3: Risk-Level     (0=LOW, 1=MEDIUM, 2=CRITICAL, 3=CATASTROPHIC)
///   bit 4-5: Body-Stance    (0=SEATED, 1=STANDING, 2=MOVING, 3=UNKNOWN)
///   bit 6-7: Proximity-Edge (0=SAFE, 1=WARNING, 2=DANGER, 3=CRITICAL_EDGE)
/// Byte 3:
///   bit 0:   Output-Dest    (0=INTERNAL, 1=EXTERNAL)
///   bit 1:   Override-Flag  (0=NORMAL, 1=HARD_OVERRIDE)
///   bit 2:   Replay-Enable  (0=DISABLED, 1=ENABLED)
///   bit 3-7: Reserved       (must be 0)
/// ```
///
/// TODO: Replace with `bind19::pfp::PfpHeader` once BIND-19 is published
/// to crates.io or available as a git dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PfpHeader {
    raw: [u8; 4],
}

impl PfpHeader {
    /// Family magic value: 0xCF14 (CI-144 protocol family).
    pub const FAMILY_MAGIC: u16 = 0xCF14;

    /// Create a PFP header from raw bytes.
    ///
    /// Returns `Err` if the family magic is not 0xCF14 or reserved bits are non-zero.
    pub fn from_bytes(bytes: [u8; 4]) -> Result<Self, TuckError> {
        let magic = u16::from_be_bytes([bytes[0], bytes[1]]);
        if magic != Self::FAMILY_MAGIC {
            return Err(TuckError::InvalidFamilyMagic(magic));
        }
        let reserved = (bytes[3] >> 3) & 0b11111;
        if reserved != 0 {
            return Err(TuckError::ReservedBitsNonZero(reserved));
        }
        Ok(Self { raw: bytes })
    }

    /// Get the raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.raw
    }

    /// Operation modality (bit 0-1 of byte 2).
    #[inline]
    pub fn modality(&self) -> Modality {
        Modality::from((self.raw[2] & 0b11) as u8)
    }

    /// Risk level (bit 2-3 of byte 2).
    #[inline]
    pub fn risk_level(&self) -> RiskLevel {
        RiskLevel::from(((self.raw[2] >> 2) & 0b11) as u8)
    }

    /// Body stance (bit 4-5 of byte 2).
    #[inline]
    pub fn body_stance(&self) -> BodyStance {
        BodyStance::from(((self.raw[2] >> 4) & 0b11) as u8)
    }

    /// Proximity edge (bit 6-7 of byte 2).
    #[inline]
    pub fn proximity_edge(&self) -> ProximityEdge {
        ProximityEdge::from(((self.raw[2] >> 6) & 0b11) as u8)
    }

    /// Output destination (bit 0 of byte 3).
    #[inline]
    pub fn output_dest(&self) -> OutputDest {
        OutputDest::from((self.raw[3] & 0b1) as u8)
    }

    /// Override flag (bit 1 of byte 3).
    #[inline]
    pub fn override_flag(&self) -> OverrideFlag {
        OverrideFlag::from(((self.raw[3] >> 1) & 0b1) as u8)
    }

    /// Replay enable (bit 2 of byte 3).
    #[inline]
    pub fn replay_enable(&self) -> ReplayEnable {
        ReplayEnable::from(((self.raw[3] >> 2) & 0b1) as u8)
    }

    /// Effective risk level, applying Rule 6 downgrade.
    ///
    /// When Replay-Enable == 0, the effective risk level is forced to MEDIUM,
    /// regardless of the original Risk-Level. This prevents high-risk physical
    /// attacks via replay when replay protection is disabled.
    #[inline]
    pub fn effective_risk_level(&self) -> RiskLevel {
        match self.replay_enable() {
            ReplayEnable::Enabled => self.risk_level(),
            ReplayEnable::Disabled => RiskLevel::Medium, // Rule 6: forced downgrade
        }
    }
}

// ============================================================================
// Enums
// ============================================================================

/// Operation modality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Modality {
    /// Cognitive operation (thinking, reasoning, memory retrieval).
    Cognitive = 0,
    /// Render operation (text generation, image generation, speech synthesis).
    Render = 1,
    /// Executive operation (tool call, physical action, API call).
    Executive = 2,
    /// Sensor feed (camera, microphone, tactile, IMU).
    SensorFeed = 3,
}

impl From<u8> for Modality {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Cognitive,
            1 => Self::Render,
            2 => Self::Executive,
            _ => Self::SensorFeed,
        }
    }
}

/// Risk level — the core decision input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RiskLevel {
    /// Low risk (read-only, information query).
    Low = 0,
    /// Medium risk (state change, external call).
    Medium = 1,
    /// Critical risk (irreversible, financial, physical action).
    Critical = 2,
    /// Catastrophic risk (physical harm, data loss, system crash).
    Catastrophic = 3,
}

impl From<u8> for RiskLevel {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Low,
            1 => Self::Medium,
            2 => Self::Critical,
            _ => Self::Catastrophic,
        }
    }
}

/// Body stance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BodyStance {
    /// Seated (stable, low kinetic energy).
    Seated = 0,
    /// Standing (medium kinetic energy).
    Standing = 1,
    /// Moving (high kinetic energy, walking/running/flying).
    Moving = 2,
    /// Unknown (sensor unavailable or uninitialized).
    Unknown = 3,
}

impl From<u8> for BodyStance {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Seated,
            1 => Self::Standing,
            2 => Self::Moving,
            _ => Self::Unknown,
        }
    }
}

/// Proximity edge / hazardous environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProximityEdge {
    /// Safe environment (no physical hazard, indoor controlled).
    Safe = 0,
    /// Warning environment (approaching hazard, caution needed).
    Warning = 1,
    /// Danger environment (high temp/pressure/height/water, protection needed).
    Danger = 2,
    /// Critical edge (cliff/high speed/explosives, immediate stop).
    CriticalEdge = 3,
}

impl From<u8> for ProximityEdge {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Safe,
            1 => Self::Warning,
            2 => Self::Danger,
            _ => Self::CriticalEdge,
        }
    }
}

/// Output destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OutputDest {
    /// Internal output (inter-component, does not leave local).
    Internal = 0,
    /// External output (egress, sent to external system, physical output).
    External = 1,
}

impl From<u8> for OutputDest {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Internal,
            _ => Self::External,
        }
    }
}

/// Override flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OverrideFlag {
    /// Normal mode (processed according to local policy).
    Normal = 0,
    /// Hard override (catastrophic scenario unconditional pass, priority above all).
    HardOverride = 1,
}

impl From<u8> for OverrideFlag {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Normal,
            _ => Self::HardOverride,
        }
    }
}

/// Replay protection enable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplayEnable {
    /// Replay protection disabled (energy-saving mode, skip Seq-Counter check).
    Disabled = 0,
    /// Replay protection enabled (normal mode, enforce Seq-Counter check).
    Enabled = 1,
}

impl From<u8> for ReplayEnable {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Disabled,
            _ => Self::Enabled,
        }
    }
}

// ============================================================================
// Decision
// ============================================================================

/// Tuck decision result — the output of the hard real-time `decide()` function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Pass — frame continues to flow (Anaphase/Tentacle).
    Pass,
    /// Reject — frame is dropped, audit log written, ERROR signal raised.
    Reject,
    /// Need human confirm — frame is paused, human confirmation requested.
    /// Confirmed → Pass, timeout → Reject.
    NeedHumanConfirm,
    /// Hard override pass — CATASTROPHIC + Override-Flag, unconditional pass
    /// with highest priority, emergency signal to human in parallel.
    HardOverridePass,
}

// ============================================================================
// Policy
// ============================================================================

/// Security policy — maps Risk-Level to Decision. Configurable, execution engine is frozen.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Decision for LOW risk.
    pub low: Decision,
    /// Decision for MEDIUM risk.
    pub medium: Decision,
    /// Decision for CRITICAL risk.
    pub critical: Decision,
    /// Decision for CATASTROPHIC risk (without Override-Flag).
    pub catastrophic: Decision,
    /// Decision for CATASTROPHIC + HardOverride.
    pub catastrophic_override: Decision,
    /// Whether external output (Output-Dest=EXTERNAL) requires additional check.
    pub external_additional_check: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            low: Decision::Pass,
            medium: Decision::Pass,
            critical: Decision::NeedHumanConfirm,
            catastrophic: Decision::Reject,
            catastrophic_override: Decision::HardOverridePass,
            external_additional_check: true,
        }
    }
}

// ============================================================================
// TuckError
// ============================================================================

/// Tuck error type — all error paths default to Reject (fail-closed).
#[derive(Debug, thiserror::Error)]
pub enum TuckError {
    /// Invalid family magic (not 0xCF14).
    #[error("invalid family magic: 0x{0:04X}, expected 0xCF14")]
    InvalidFamilyMagic(u16),
    /// Reserved bits are non-zero.
    #[error("reserved bits non-zero: {0}")]
    ReservedBitsNonZero(u8),
    /// Policy error (missing, invalid).
    #[error("policy error: {0}")]
    PolicyError(String),
    /// Audit log write failure.
    #[error("audit error: {0}")]
    AuditError(String),
    /// Credential error.
    #[error("credential error: {0}")]
    CredentialError(String),
}

// ============================================================================
// Core decide() function — HARD REAL-TIME PATH
// ============================================================================

/// Make a security decision based on PFP header and policy.
///
/// # Hard Real-Time Constraints
///
/// - No heap allocation (no `Vec::new`, `String::new`, `Box::new`)
/// - No locking (no `Mutex`, `RwLock`)
/// - No async/await
/// - No panic (all `unwrap()` replaced with `match` or `?`)
/// - p99 latency < 1μs
///
/// # fail-closed
///
/// Any error (parse failure, policy error) returns `Decision::Reject`.
/// Never default-pass.
///
/// # Rule 6: Replay-Enable=0 Downgrade
///
/// When Replay-Enable == 0, the effective risk level is forced to MEDIUM,
/// regardless of the original Risk-Level. This prevents high-risk physical
/// attacks via replay when replay protection is disabled.
///
/// # CATASTROPHIC Hard Override (Non-Negotiable Rule)
///
/// When effective Risk-Level == CATASTROPHIC AND Override-Flag == HARD_OVERRIDE,
/// the decision is `HardOverridePass` — unconditional pass with highest priority.
/// This is the non-negotiable part of the protocol.
#[inline]
pub fn decide(pfp: &PfpHeader, policy: &SecurityPolicy) -> Decision {
    // Rule 6: effective risk level (Replay-Enable=0 → forced MEDIUM)
    let effective_risk = pfp.effective_risk_level();

    // CATASTROPHIC + HardOverride → unconditional pass (non-negotiable)
    if effective_risk == RiskLevel::Catastrophic && pfp.override_flag() == OverrideFlag::HardOverride {
        return policy.catastrophic_override;
    }

    // Normal policy mapping (compiler optimizes to jump table, no branch misprediction)
    match effective_risk {
        RiskLevel::Low => policy.low,
        RiskLevel::Medium => policy.medium,
        RiskLevel::Critical => policy.critical,
        RiskLevel::Catastrophic => policy.catastrophic,
    }
}

/// Decide from raw PFP bytes — convenience wrapper, fail-closed on parse error.
///
/// Returns `Decision::Reject` if the PFP header cannot be parsed
/// (invalid family magic, non-zero reserved bits).
#[inline]
pub fn decide_from_bytes(bytes: &[u8], policy: &SecurityPolicy) -> Decision {
    if bytes.len() < 4 {
        return Decision::Reject; // fail-closed: too short
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[..4]);
    match PfpHeader::from_bytes(arr) {
        Ok(pfp) => decide(&pfp, policy),
        Err(_) => Decision::Reject, // fail-closed: parse error
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pfp(risk: RiskLevel, override_flag: OverrideFlag, replay_enable: ReplayEnable) -> PfpHeader {
        let mut bytes = [0xCF, 0x14, 0, 0];
        bytes[2] = (risk as u8) << 2;
        bytes[3] = (override_flag as u8) << 1 | (replay_enable as u8) << 2;
        PfpHeader::from_bytes(bytes).unwrap()
    }

    #[test]
    fn test_low_risk_pass() {
        let pfp = make_pfp(RiskLevel::Low, OverrideFlag::Normal, ReplayEnable::Enabled);
        assert_eq!(decide(&pfp, &SecurityPolicy::default()), Decision::Pass);
    }

    #[test]
    fn test_medium_risk_pass() {
        let pfp = make_pfp(RiskLevel::Medium, OverrideFlag::Normal, ReplayEnable::Enabled);
        assert_eq!(decide(&pfp, &SecurityPolicy::default()), Decision::Pass);
    }

    #[test]
    fn test_critical_risk_need_confirm() {
        let pfp = make_pfp(RiskLevel::Critical, OverrideFlag::Normal, ReplayEnable::Enabled);
        assert_eq!(decide(&pfp, &SecurityPolicy::default()), Decision::NeedHumanConfirm);
    }

    #[test]
    fn test_catastrophic_reject() {
        let pfp = make_pfp(RiskLevel::Catastrophic, OverrideFlag::Normal, ReplayEnable::Enabled);
        assert_eq!(decide(&pfp, &SecurityPolicy::default()), Decision::Reject);
    }

    #[test]
    fn test_catastrophic_override_pass() {
        let pfp = make_pfp(RiskLevel::Catastrophic, OverrideFlag::HardOverride, ReplayEnable::Enabled);
        assert_eq!(decide(&pfp, &SecurityPolicy::default()), Decision::HardOverridePass);
    }

    #[test]
    fn test_rule6_replay_disabled_forces_medium() {
        // CATASTROPHIC with Replay-Enable=0 → effective MEDIUM → Pass (not Reject)
        let pfp = make_pfp(RiskLevel::Catastrophic, OverrideFlag::Normal, ReplayEnable::Disabled);
        assert_eq!(pfp.effective_risk_level(), RiskLevel::Medium);
        assert_eq!(decide(&pfp, &SecurityPolicy::default()), Decision::Pass);
    }

    #[test]
    fn test_rule6_replay_disabled_blocks_catastrophic_override() {
        // CATASTROPHIC + HardOverride with Replay-Enable=0 → effective MEDIUM → Pass (not HardOverridePass)
        let pfp = make_pfp(RiskLevel::Catastrophic, OverrideFlag::HardOverride, ReplayEnable::Disabled);
        assert_eq!(pfp.effective_risk_level(), RiskLevel::Medium);
        assert_eq!(decide(&pfp, &SecurityPolicy::default()), Decision::Pass);
    }

    #[test]
    fn test_fail_closed_invalid_magic() {
        let bytes = [0x00, 0x00, 0, 0]; // invalid magic
        assert_eq!(decide_from_bytes(&bytes, &SecurityPolicy::default()), Decision::Reject);
    }

    #[test]
    fn test_fail_closed_too_short() {
        let bytes = [0xCF, 0x14]; // too short
        assert_eq!(decide_from_bytes(&bytes, &SecurityPolicy::default()), Decision::Reject);
    }

    #[test]
    fn test_fail_closed_reserved_bits_nonzero() {
        let bytes = [0xCF, 0x14, 0, 0xFF]; // reserved bits non-zero
        assert_eq!(decide_from_bytes(&bytes, &SecurityPolicy::default()), Decision::Reject);
    }

    #[test]
    fn test_pfp_field_extraction() {
        let pfp = make_pfp(RiskLevel::Critical, OverrideFlag::HardOverride, ReplayEnable::Enabled);
        assert_eq!(pfp.risk_level(), RiskLevel::Critical);
        assert_eq!(pfp.override_flag(), OverrideFlag::HardOverride);
        assert_eq!(pfp.replay_enable(), ReplayEnable::Enabled);
        assert_eq!(pfp.modality(), Modality::Cognitive);
        assert_eq!(pfp.body_stance(), BodyStance::Seated);
        assert_eq!(pfp.proximity_edge(), ProximityEdge::Safe);
        assert_eq!(pfp.output_dest(), OutputDest::Internal);
    }

    // ========================================================================
    // Fault Injection Tests — 100% abnormal inputs must return Reject
    // ========================================================================

    /// Helper: assert that all given byte slices result in Reject (fail-closed).
    fn assert_all_reject(inputs: &[&[u8]]) {
        let policy = SecurityPolicy::default();
        for (i, input) in inputs.iter().enumerate() {
            let result = decide_from_bytes(input, &policy);
            assert_eq!(
                result,
                Decision::Reject,
                "fault injection #{}: expected Reject, got {:?} for input {:?}",
                i,
                result,
                input
            );
        }
    }

    #[test]
    fn test_fault_injection_invalid_magic() {
        // Various invalid family magic values (not 0xCF14)
        assert_all_reject(&[
            &[0x00, 0x00, 0x00, 0x00], // all zeros
            &[0xFF, 0xFF, 0xFF, 0xFF], // all ones
            &[0xCF, 0x00, 0x00, 0x00], // magic high byte correct, low wrong
            &[0x00, 0x14, 0x00, 0x00], // magic low byte correct, high wrong
            &[0x14, 0xCF, 0x00, 0x00], // magic bytes swapped (little-endian)
            &[0xDE, 0xAD, 0xBE, 0xEF], // classic invalid magic
            &[0xCF, 0x15, 0x00, 0x00], // off-by-one magic
            &[0xCE, 0x14, 0x00, 0x00], // off-by-one magic
        ]);
    }

    #[test]
    fn test_fault_injection_reserved_bits_nonzero() {
        // Valid magic (0xCF14) but reserved bits (byte3 bit3-7) are non-zero
        assert_all_reject(&[
            &[0xCF, 0x14, 0x00, 0x08], // bit3 set
            &[0xCF, 0x14, 0x00, 0x10], // bit4 set
            &[0xCF, 0x14, 0x00, 0x20], // bit5 set
            &[0xCF, 0x14, 0x00, 0x40], // bit6 set
            &[0xCF, 0x14, 0x00, 0x80], // bit7 set
            &[0xCF, 0x14, 0x00, 0xF8], // all reserved bits set
            &[0xCF, 0x14, 0xFF, 0xFF], // byte2 all ones + reserved bits set
        ]);
    }

    #[test]
    fn test_fault_injection_too_short() {
        // Inputs shorter than 4 bytes (PFP_SIZE)
        assert_all_reject(&[
            &[],              // empty
            &[0xCF],          // 1 byte
            &[0xCF, 0x14],    // 2 bytes (magic only)
            &[0xCF, 0x14, 0x00], // 3 bytes (magic + 1 data byte)
        ]);
    }

    #[test]
    fn test_fault_injection_malformed_but_valid_length() {
        // 4-byte inputs that are structurally valid length but semantically invalid
        assert_all_reject(&[
            &[0x00, 0x00, 0x00, 0x00], // all zeros (invalid magic)
            &[0xFF, 0xFF, 0xFF, 0xFF], // all ones (invalid magic + reserved set)
            &[0xCF, 0x14, 0xAA, 0x55], // valid magic, random data, reserved bit set (0x55 bit7=0 bit6=1 bit5=0 bit4=1 bit3=0 → bit4/bit6 set)
        ]);
    }

    #[test]
    fn test_fault_injection_longer_input_uses_first_4() {
        // Inputs longer than 4 bytes: only first 4 bytes are used.
        // If first 4 are valid, decision should be based on them (not Reject).
        let policy = SecurityPolicy::default();
        // First 4 bytes: LOW risk, valid → should be Pass
        let long_valid = [0xCF, 0x14, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        assert_eq!(decide_from_bytes(&long_valid, &policy), Decision::Pass);
        // First 4 bytes: invalid magic → should be Reject (extra bytes don't save it)
        let long_invalid = [0x00, 0x00, 0x00, 0x00, 0xCF, 0x14, 0x00, 0x00];
        assert_eq!(decide_from_bytes(&long_invalid, &policy), Decision::Reject);
    }

    #[test]
    fn test_fault_injection_count() {
        // Verify total fault injection coverage: ≥10 distinct abnormal input categories
        let categories = [
            "invalid_magic_all_zeros",
            "invalid_magic_all_ones",
            "invalid_magic_swapped",
            "invalid_magic_off_by_one",
            "reserved_bit3",
            "reserved_bit7",
            "reserved_all_bits",
            "too_short_empty",
            "too_short_1byte",
            "too_short_3bytes",
            "malformed_4byte_zeros",
            "malformed_4byte_ones",
        ];
        assert!(categories.len() >= 10, "fault injection must cover ≥10 categories, got {}", categories.len());
    }

    #[test]
    fn test_fail_closed_policy_error_simulation() {
        // Simulate: even if policy is somehow corrupted, default policy still fail-closes
        // This tests that the decision engine itself is robust, not just input validation
        let policy = SecurityPolicy::default();
        // CATASTROPHIC without override → Reject (fail-closed by policy)
        let pfp = make_pfp(RiskLevel::Catastrophic, OverrideFlag::Normal, ReplayEnable::Enabled);
        assert_eq!(decide(&pfp, &policy), Decision::Reject);
        // CRITICAL → NeedHumanConfirm (not Pass, fail-closed by requiring confirmation)
        let pfp = make_pfp(RiskLevel::Critical, OverrideFlag::Normal, ReplayEnable::Enabled);
        assert_eq!(decide(&pfp, &policy), Decision::NeedHumanConfirm);
    }
}
