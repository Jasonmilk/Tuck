//! HSM/TPM trait definitions — reserved for production hardware-backed credential storage.
//!
//! # Design Principle
//!
//! **极致解耦**: HSM/TPM support is defined as traits, not implementations.
//! Tuck core depends only on `CredentialStore` — HSM backends implement it.
//!
//! **物理事实优先**: HSM/TPM operations are hardware-backed. The traits
//! define WHAT operations are needed, not HOW they're implemented.
//!
//! **渐进生长**: These traits are reserved for P3+ (future). Current
//! implementation uses `FileCredentialStore` for development. HSM backends
//! will be implemented when hardware is available.
//!
//! # Trait Hierarchy
//!
//! ```text
//! CredentialStore (core trait)
//! ├── FileCredentialStore (development, AES-256-GCM encrypted file)
//! ├── HsmCredentialStore (production, hardware-backed)
//! │   ├── CloudHsmStore (AWS CloudHSM)
//! │   ├── Pkcs11Store (PKCS#11 compatible HSM)
//! │   └── TpmStore (TPM 2.0)
//! └── VaultCredentialStore (HashiCorp Vault)
//! ```

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::credential::{Credential, CredentialError, IdentityLabel};

// Re-export CredentialStore for convenience
pub use crate::credential::CredentialStore;

// ============================================================================
// HSM Credential Store
// ============================================================================

/// HSM-backed credential store.
///
/// Extends `CredentialStore` with HSM-specific operations.
/// Implementations: AWS CloudHSM, PKCS#11, Azure Key Vault HSM, etc.
///
/// # Reserved for Future
///
/// This trait is defined but not implemented in the current version.
/// It will be implemented when hardware HSM support is required.
#[async_trait]
pub trait HsmCredentialStore: CredentialStore {
    /// HSM manufacturer/type identifier.
    fn hsm_type(&self) -> &str;

    /// Check if the HSM connection is healthy.
    async fn health_check(&self) -> Result<HsmHealth, CredentialError>;

    /// Generate a new key pair inside the HSM (never leaves HSM boundary).
    async fn generate_key_pair(
        &self,
        label: &IdentityLabel,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyHandle, CredentialError>;

    /// Sign data using a key stored in the HSM (key never leaves HSM).
    async fn sign(
        &self,
        handle: &KeyHandle,
        data: &[u8],
    ) -> Result<Signature, CredentialError>;

    /// Decrypt data using a key stored in the HSM.
    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialError>;
}

/// HSM health status.
#[derive(Debug, Clone)]
pub struct HsmHealth {
    /// Whether the HSM is connected and responsive.
    pub connected: bool,
    /// HSM firmware version.
    pub firmware_version: String,
    /// Number of active sessions.
    pub active_sessions: u32,
    /// Last health check timestamp (unix seconds).
    pub last_check: u64,
}

/// Key algorithm for HSM key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// RSA with specified key size.
    Rsa { bits: u32 },
    /// ECDSA with specified curve.
    Ecdsa { curve: EcCurve },
    /// AES with specified key size.
    Aes { bits: u32 },
}

/// Elliptic curve for ECDSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// NIST P-521.
    P521,
}

/// Opaque handle to a key stored in the HSM.
///
/// The actual key material never leaves the HSM. This handle is just
/// a reference that the HSM can resolve.
#[derive(Debug, Clone)]
pub struct KeyHandle {
    /// HSM-specific key identifier.
    pub id: Vec<u8>,
    /// Key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Whether the key is extractable (should be false for production).
    pub extractable: bool,
}

/// Cryptographic signature produced by HSM.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Signature bytes.
    pub bytes: Vec<u8>,
    /// Signature algorithm.
    pub algorithm: KeyAlgorithm,
}

// ============================================================================
// TPM 2.0 Support
// ============================================================================

/// TPM 2.0 credential store.
///
/// Uses Trusted Platform Module for secure credential storage and
/// platform attestation.
///
/// # Reserved for Future
///
/// This trait is defined but not implemented in the current version.
#[async_trait]
pub trait TpmCredentialStore: CredentialStore {
    /// TPM manufacturer (e.g., "Intel", "AMD", "Microsoft").
    fn tpm_manufacturer(&self) -> &str;

    /// TPM specification version (e.g., "2.0").
    fn tpm_version(&self) -> &str;

    /// Read a Platform Configuration Register (PCR).
    ///
    /// PCRs contain measurements of system state (boot chain, firmware, etc.).
    /// They can be used to verify system integrity before releasing credentials.
    async fn read_pcr(&self, index: u32) -> Result<PcrValue, CredentialError>;

    /// Perform remote attestation — produce a quote signed by the TPM's
    /// Attestation Key (AK), proving the current PCR values.
    async fn attest(
        &self,
        pcr_indices: &[u32],
        nonce: &[u8],
    ) -> Result<AttestationQuote, CredentialError>;

    /// Seal data to PCR values — data can only be unsealed when PCRs
    /// match the expected values (system in known-good state).
    async fn seal_to_pcr(
        &self,
        label: &IdentityLabel,
        data: &[u8],
        pcr_policy: &PcrPolicy,
    ) -> Result<(), CredentialError>;

    /// Unseal data — only succeeds if current PCR values match the policy.
    async fn unseal_from_pcr(
        &self,
        label: &IdentityLabel,
    ) -> Result<Credential, CredentialError>;
}

/// PCR value (SHA-256 hash, 32 bytes).
#[derive(Debug, Clone)]
pub struct PcrValue {
    /// PCR index.
    pub index: u32,
    /// PCR value (32 bytes for SHA-256).
    pub value: [u8; 32],
}

/// Attestation quote signed by TPM.
#[derive(Debug, Clone)]
pub struct AttestationQuote {
    /// Quote data (contains PCR values and nonce).
    pub quote: Vec<u8>,
    /// Signature over the quote (by Attestation Key).
    pub signature: Vec<u8>,
    /// Attestation Key public certificate (for verification).
    pub ak_certificate: Vec<u8>,
}

/// PCR policy — defines which PCR values must match for unsealing.
#[derive(Debug, Clone)]
pub struct PcrPolicy {
    /// Map of PCR index → expected value.
    pub expected_pcrs: std::collections::HashMap<u32, [u8; 32]>,
}

impl PcrPolicy {
    /// Create an empty PCR policy.
    pub fn new() -> Self {
        Self {
            expected_pcrs: std::collections::HashMap::new(),
        }
    }

    /// Add a PCR expectation.
    pub fn with_pcr(mut self, index: u32, value: [u8; 32]) -> Self {
        self.expected_pcrs.insert(index, value);
        self
    }
}

impl Default for PcrPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests (trait compile-time verification)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // These tests verify that the traits are object-safe and can be
    // used as trait objects. They don't test actual HSM/TPM hardware.

    #[test]
    fn test_hsm_trait_object_safe() {
        // Verify HsmCredentialStore can be used as a trait object
        fn _accept_hsm(_store: &dyn HsmCredentialStore) {}
    }

    #[test]
    fn test_tpm_trait_object_safe() {
        // Verify TpmCredentialStore can be used as a trait object
        fn _accept_tpm(_store: &dyn TpmCredentialStore) {}
    }

    #[test]
    fn test_key_algorithm_variants() {
        let rsa = KeyAlgorithm::Rsa { bits: 2048 };
        let ecdsa = KeyAlgorithm::Ecdsa { curve: EcCurve::P256 };
        let aes = KeyAlgorithm::Aes { bits: 256 };

        assert_ne!(rsa, ecdsa);
        assert_ne!(ecdsa, aes);
    }

    #[test]
    fn test_ec_curve_variants() {
        assert_ne!(EcCurve::P256, EcCurve::P384);
        assert_ne!(EcCurve::P384, EcCurve::P521);
    }

    #[test]
    fn test_pcr_policy_builder() {
        let policy = PcrPolicy::new()
            .with_pcr(0, [0u8; 32])
            .with_pcr(7, [1u8; 32]);

        assert_eq!(policy.expected_pcrs.len(), 2);
        assert!(policy.expected_pcrs.contains_key(&0));
        assert!(policy.expected_pcrs.contains_key(&7));
    }

    #[test]
    fn test_hsm_health_struct() {
        let health = HsmHealth {
            connected: true,
            firmware_version: "1.2.3".to_string(),
            active_sessions: 5,
            last_check: 1234567890,
        };

        assert!(health.connected);
        assert_eq!(health.firmware_version, "1.2.3");
        assert_eq!(health.active_sessions, 5);
    }

    #[test]
    fn test_key_handle_struct() {
        let handle = KeyHandle {
            id: vec![1, 2, 3],
            algorithm: KeyAlgorithm::Aes { bits: 256 },
            extractable: false,
        };

        assert_eq!(handle.id, vec![1, 2, 3]);
        assert!(!handle.extractable);
    }

    #[test]
    fn test_signature_struct() {
        let sig = Signature {
            bytes: vec![4, 5, 6],
            algorithm: KeyAlgorithm::Ecdsa { curve: EcCurve::P256 },
        };

        assert_eq!(sig.bytes.len(), 3);
    }

    #[test]
    fn test_pcr_value_struct() {
        let pcr = PcrValue {
            index: 7,
            value: [0u8; 32],
        };

        assert_eq!(pcr.index, 7);
        assert_eq!(pcr.value.len(), 32);
    }

    #[test]
    fn test_attestation_quote_struct() {
        let quote = AttestationQuote {
            quote: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            ak_certificate: vec![7, 8, 9],
        };

        assert_eq!(quote.quote.len(), 3);
        assert_eq!(quote.signature.len(), 3);
        assert_eq!(quote.ak_certificate.len(), 3);
    }
}
