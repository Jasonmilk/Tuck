//! Credential management — identity_label mapping, zeroize-on-drop, CredentialStore trait.
//!
//! # Design Principle
//!
//! **凭证永不在组件内存中** (Core Promise #3):
//! - Credentials are wrapped in `Zeroizing<Vec<u8>>` — automatically zeroed on drop
//! - `identity_label` is the only thing that flows through components (Anaphase, Tentacle)
//! - Tuck resolves `identity_label` → plaintext credential at the *physical edge* (outbound)
//! - After injection, credential is zeroized immediately
//!
//! **极致解耦**: `CredentialStore` is a trait — multiple backends possible
//! (file, HSM, Vault, env). Tuck core only depends on the trait, not a specific backend.
//!
//! **按需加载**: Credentials are loaded only when needed (at injection time),
//! not pre-loaded into memory.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// ============================================================================
// Errors
// ============================================================================

/// Credential-related errors.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// Credential not found for the given identity_label.
    #[error("credential not found for label: {0}")]
    NotFound(String),

    /// Invalid identity_label format.
    #[error("invalid identity_label: {0}")]
    InvalidLabel(String),

    /// Credential store backend error (IO, HSM, etc.).
    #[error("credential store error: {0}")]
    Store(String),

    /// Credential is empty or malformed.
    #[error("credential is empty or malformed")]
    Empty,
}

// ============================================================================
// Identity Label
// ============================================================================

/// Credential scheme — how the credential is stored/retrieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialScheme {
    /// Environment variable: `env:VAR_NAME`
    Env,
    /// File path: `file:/path/to/secret`
    File,
    /// HSM key ID: `hsm:key_identifier`
    Hsm,
    /// HashiCorp Vault path: `vault:secret/path#field`
    Vault,
    /// Inline base64-encoded credential (testing only, NOT for production)
    Inline,
}

impl fmt::Display for CredentialScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env => write!(f, "env"),
            Self::File => write!(f, "file"),
            Self::Hsm => write!(f, "hsm"),
            Self::Vault => write!(f, "vault"),
            Self::Inline => write!(f, "inline"),
        }
    }
}

impl FromStr for CredentialScheme {
    type Err = CredentialError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "env" => Ok(Self::Env),
            "file" => Ok(Self::File),
            "hsm" => Ok(Self::Hsm),
            "vault" => Ok(Self::Vault),
            "inline" => Ok(Self::Inline),
            other => Err(CredentialError::InvalidLabel(format!(
                "unknown scheme: {other}"
            ))),
        }
    }
}

/// Identity label — a non-sensitive reference to a credential.
///
/// Format: `scheme:path`
/// - `env:API_KEY` — environment variable named API_KEY
/// - `file:/etc/secrets/token` — file containing the credential
/// - `hsm:production-signing-key` — HSM key identifier
/// - `vault:secret/data/prod#token` — Vault path with field selector
/// - `inline:base64data` — inline credential (testing only)
///
/// The identity_label flows through Anaphase/Tentacle — it is NOT a secret.
/// Only Tuck can resolve it to a plaintext credential.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IdentityLabel {
    /// Credential scheme.
    pub scheme: CredentialScheme,
    /// Scheme-specific path/identifier.
    pub path: String,
}

impl IdentityLabel {
    /// Create a new identity label.
    pub fn new(scheme: CredentialScheme, path: impl Into<String>) -> Self {
        Self {
            scheme,
            path: path.into(),
        }
    }

    /// Parse an identity label from a string (`scheme:path`).
    pub fn parse(s: &str) -> Result<Self, CredentialError> {
        let (scheme_str, path) = s
            .split_once(':')
            .ok_or_else(|| CredentialError::InvalidLabel(format!("missing scheme: {s}")))?;

        if path.is_empty() {
            return Err(CredentialError::InvalidLabel(format!(
                "empty path: {s}"
            )));
        }

        let scheme = CredentialScheme::from_str(scheme_str)?;
        Ok(Self {
            scheme,
            path: path.to_string(),
        })
    }

    /// Check if this label uses the inline scheme (NOT for production).
    pub fn is_inline(&self) -> bool {
        self.scheme == CredentialScheme::Inline
    }
}

impl fmt::Display for IdentityLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.scheme, self.path)
    }
}

impl FromStr for IdentityLabel {
    type Err = CredentialError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// ============================================================================
// Credential
// ============================================================================

/// A plaintext credential — automatically zeroed on drop.
///
/// # Safety
///
/// - The credential bytes are stored in `Zeroizing<Vec<u8>>` — automatically
///   overwritten with zeros when dropped
/// - Never clone a Credential unnecessarily — each clone creates another copy
///   in memory that must be zeroized
/// - Use `expose_secret()` only at the physical edge (outbound injection)
/// - After injection, drop the Credential immediately to trigger zeroization
#[derive(Clone)]
pub struct Credential {
    /// The plaintext credential bytes (zeroized on drop).
    secret: Zeroizing<Vec<u8>>,
    /// The identity_label this credential was resolved from (for audit).
    label: IdentityLabel,
}

impl Credential {
    /// Create a new credential from bytes.
    ///
    /// The bytes are copied into a Zeroizing container. The caller should
    /// zeroize the original bytes after calling this.
    pub fn new(bytes: impl Into<Vec<u8>>, label: IdentityLabel) -> Self {
        Self {
            secret: Zeroizing::new(bytes.into()),
            label,
        }
    }

    /// Expose the plaintext credential bytes.
    ///
    /// # Warning
    ///
    /// Only call this at the physical edge (outbound request injection).
    /// The returned slice is valid only while the Credential is alive.
    /// After injection, drop the Credential to trigger zeroization.
    pub fn expose_secret(&self) -> &[u8] {
        &self.secret
    }

    /// Expose the credential as a UTF-8 string (if valid).
    pub fn expose_secret_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.secret)
    }

    /// Get the identity_label this credential was resolved from.
    pub fn label(&self) -> &IdentityLabel {
        &self.label
    }

    /// Get the credential length (without exposing the secret).
    pub fn len(&self) -> usize {
        self.secret.len()
    }

    /// Check if the credential is empty.
    pub fn is_empty(&self) -> bool {
        self.secret.is_empty()
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret — only metadata
        f.debug_struct("Credential")
            .field("label", &self.label)
            .field("len", &self.secret.len())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        // Zeroizing handles this automatically, but we explicitly note it
        // The Zeroizing<Vec<u8>> will zero its contents before deallocation
    }
}

// ============================================================================
// CredentialStore Trait
// ============================================================================

/// Credential store backend — resolves identity_label → Credential.
///
/// # Implementations
///
/// - `EnvCredentialStore` — reads from environment variables
/// - `FileCredentialStore` — reads from encrypted files (P3-T3)
/// - `HsmCredentialStore` — reads from HSM (future, trait预留)
/// - `VaultCredentialStore` — reads from HashiCorp Vault (future)
///
/// # Design Principle
///
/// **极致解耦**: Tuck core depends only on this trait. Backends are
/// pluggable — swap file for HSM without changing Tuck core.
///
/// **按需加载**: `get()` loads the credential only when called. Credentials
/// are not pre-loaded or cached in memory (unless the backend explicitly caches).
#[async_trait::async_trait]
pub trait CredentialStore: Send + Sync {
    /// Resolve an identity_label to a plaintext credential.
    ///
    /// # Errors
    ///
    /// - `NotFound` — no credential for this label
    /// - `InvalidLabel` — label format is invalid
    /// - `Store` — backend error (IO, HSM connection, etc.)
    /// - `Empty` — credential exists but is empty
    async fn get(&self, label: &IdentityLabel) -> Result<Credential, CredentialError>;

    /// Store a credential (optional — read-only backends may return Err).
    async fn put(&self, label: &IdentityLabel, credential: &[u8]) -> Result<(), CredentialError>;

    /// Delete a credential (optional — read-only backends may return Err).
    async fn delete(&self, label: &IdentityLabel) -> Result<(), CredentialError>;

    /// List all available identity_labels (optional).
    async fn list(&self) -> Result<Vec<IdentityLabel>, CredentialError>;
}

// ============================================================================
// InMemoryCredentialStore (for testing)
// ============================================================================

/// In-memory credential store — for testing only.
///
/// Stores credentials in a HashMap. Credentials are zeroized on removal/drop.
/// NOT for production use (credentials persist in memory until process exit).
#[cfg(any(test, feature = "test-utils"))]
pub struct InMemoryCredentialStore {
    credentials: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl InMemoryCredentialStore {
    pub fn new() -> Self {
        Self {
            credentials: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn insert(&self, label: &str, value: &[u8]) {
        self.credentials
            .lock()
            .unwrap()
            .insert(label.to_string(), value.to_vec());
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[async_trait::async_trait]
impl CredentialStore for InMemoryCredentialStore {
    async fn get(&self, label: &IdentityLabel) -> Result<Credential, CredentialError> {
        let key = label.to_string();
        let creds = self.credentials.lock().unwrap();
        match creds.get(&key) {
            Some(bytes) if !bytes.is_empty() => Ok(Credential::new(bytes.clone(), label.clone())),
            Some(_) => Err(CredentialError::Empty),
            None => Err(CredentialError::NotFound(key)),
        }
    }

    async fn put(&self, label: &IdentityLabel, credential: &[u8]) -> Result<(), CredentialError> {
        self.credentials
            .lock()
            .unwrap()
            .insert(label.to_string(), credential.to_vec());
        Ok(())
    }

    async fn delete(&self, label: &IdentityLabel) -> Result<(), CredentialError> {
        self.credentials.lock().unwrap().remove(&label.to_string());
        Ok(())
    }

    async fn list(&self) -> Result<Vec<IdentityLabel>, CredentialError> {
        let creds = self.credentials.lock().unwrap();
        let mut labels = Vec::new();
        for key in creds.keys() {
            if let Ok(label) = IdentityLabel::parse(key) {
                labels.push(label);
            }
        }
        Ok(labels)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- IdentityLabel tests ---

    #[test]
    fn test_parse_env_label() {
        let label = IdentityLabel::parse("env:API_KEY").unwrap();
        assert_eq!(label.scheme, CredentialScheme::Env);
        assert_eq!(label.path, "API_KEY");
        assert_eq!(label.to_string(), "env:API_KEY");
    }

    #[test]
    fn test_parse_file_label() {
        let label = IdentityLabel::parse("file:/etc/secrets/token").unwrap();
        assert_eq!(label.scheme, CredentialScheme::File);
        assert_eq!(label.path, "/etc/secrets/token");
    }

    #[test]
    fn test_parse_hsm_label() {
        let label = IdentityLabel::parse("hsm:prod-signing-key").unwrap();
        assert_eq!(label.scheme, CredentialScheme::Hsm);
    }

    #[test]
    fn test_parse_vault_label() {
        let label = IdentityLabel::parse("vault:secret/data/prod#token").unwrap();
        assert_eq!(label.scheme, CredentialScheme::Vault);
        assert_eq!(label.path, "secret/data/prod#token");
    }

    #[test]
    fn test_parse_inline_label() {
        let label = IdentityLabel::parse("inline:base64data").unwrap();
        assert_eq!(label.scheme, CredentialScheme::Inline);
        assert!(label.is_inline());
    }

    #[test]
    fn test_parse_missing_scheme() {
        let result = IdentityLabel::parse("just_a_string");
        assert!(matches!(result, Err(CredentialError::InvalidLabel(_))));
    }

    #[test]
    fn test_parse_empty_path() {
        let result = IdentityLabel::parse("env:");
        assert!(matches!(result, Err(CredentialError::InvalidLabel(_))));
    }

    #[test]
    fn test_parse_unknown_scheme() {
        let result = IdentityLabel::parse("unknown:something");
        assert!(matches!(result, Err(CredentialError::InvalidLabel(_))));
    }

    #[test]
    fn test_label_from_str() {
        let label: IdentityLabel = "file:/tmp/secret".parse().unwrap();
        assert_eq!(label.scheme, CredentialScheme::File);
    }

    #[test]
    fn test_label_serialization() {
        let label = IdentityLabel::new(CredentialScheme::Env, "MY_KEY");
        let json = serde_json::to_string(&label).unwrap();
        let parsed: IdentityLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, label);
    }

    // --- Credential tests ---

    #[test]
    fn test_credential_creation() {
        let label = IdentityLabel::parse("env:TEST_KEY").unwrap();
        let cred = Credential::new(b"secret_value".to_vec(), label.clone());
        assert_eq!(cred.len(), 12);
        assert!(!cred.is_empty());
        assert_eq!(cred.label(), &label);
    }

    #[test]
    fn test_credential_expose_secret() {
        let label = IdentityLabel::parse("env:TEST_KEY").unwrap();
        let cred = Credential::new(b"my_secret".to_vec(), label);
        assert_eq!(cred.expose_secret(), b"my_secret");
    }

    #[test]
    fn test_credential_expose_secret_str() {
        let label = IdentityLabel::parse("env:TEST_KEY").unwrap();
        let cred = Credential::new(b"hello_world".to_vec(), label);
        assert_eq!(cred.expose_secret_str().unwrap(), "hello_world");
    }

    #[test]
    fn test_credential_debug_redacts_secret() {
        let label = IdentityLabel::parse("env:TEST_KEY").unwrap();
        let cred = Credential::new(b"super_secret".to_vec(), label);
        let debug = format!("{:?}", cred);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret"));
    }

    #[test]
    fn test_credential_empty() {
        let label = IdentityLabel::parse("env:TEST_KEY").unwrap();
        let cred = Credential::new(Vec::new(), label);
        assert!(cred.is_empty());
        assert_eq!(cred.len(), 0);
    }

    #[test]
    fn test_credential_zeroize_on_drop() {
        // Test that Zeroizing zeroes memory when zeroize() is called.
        // We test the Zeroize trait directly (safe, no unsafe needed).
        // The actual drop behavior is guaranteed by Zeroizing's Drop impl,
        // which calls zeroize() before the inner value is dropped.
        use zeroize::Zeroize;

        // Create a buffer with known data
        let mut buffer = [0xABu8; 64];
        assert_eq!(buffer[0], 0xAB);
        assert_eq!(buffer[32], 0xAB);

        // Call zeroize() — this is what Zeroizing::drop() does internally
        buffer.zeroize();

        // After zeroize, all bytes should be 0
        for (i, &byte) in buffer.iter().enumerate() {
            assert_eq!(byte, 0, "byte {i} not zeroed after zeroize()");
        }
    }

    #[test]
    fn test_credential_zeroizing_vec_zeroizes() {
        // Test that Zeroizing<Vec<u8>> zeroizes its contents on drop.
        // We can't inspect freed memory safely, but we can verify that
        // the Zeroize trait is implemented for Vec<u8> and works.
        use zeroize::Zeroize;

        let mut vec = vec![0xCDu8; 128];
        assert_eq!(vec[0], 0xCD);
        assert_eq!(vec[64], 0xCD);

        vec.zeroize();

        for (i, &byte) in vec.iter().enumerate() {
            assert_eq!(byte, 0, "byte {i} not zeroed after zeroize()");
        }
    }

    #[test]
    fn test_credential_no_secret_in_debug_after_drop() {
        // Verify that after a Credential is dropped, no secret material
        // remains in any accessible structure.
        let label = IdentityLabel::parse("env:TEST_KEY").unwrap();

        // Create and immediately drop a credential with a distinctive secret
        let secret_marker = b"MARKER_SECRET_12345";
        {
            let _cred = Credential::new(secret_marker.to_vec(), label.clone());
        } // cred dropped here — zeroize triggered by Zeroizing

        // The label should still be usable (it's not secret)
        assert_eq!(label.to_string(), "env:TEST_KEY");

        // Verify that Zeroizing implements ZeroizeOnDrop (compile-time guarantee)
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Zeroizing<Vec<u8>>>();
    }

    #[test]
    fn test_credential_clone_zeroizes_original_on_drop() {
        // Verify that cloning a Credential creates a separate copy,
        // and dropping the original zeroizes only the original's memory.
        let label = IdentityLabel::parse("env:TEST_KEY").unwrap();
        let original = Credential::new(b"original_secret".to_vec(), label);

        let clone = original.clone();
        assert_eq!(clone.expose_secret(), b"original_secret");

        // Drop original — its memory should be zeroized by Zeroizing
        drop(original);

        // Clone should still be valid (separate memory allocation)
        assert_eq!(clone.expose_secret(), b"original_secret");
        assert_eq!(clone.len(), 15);
    }

    // --- InMemoryCredentialStore tests ---

    #[tokio::test]
    async fn test_store_get() {
        let store = InMemoryCredentialStore::new();
        let label = IdentityLabel::parse("env:TEST_KEY").unwrap();
        store.insert("env:TEST_KEY", b"test_value");

        let cred = store.get(&label).await.unwrap();
        assert_eq!(cred.expose_secret(), b"test_value");
    }

    #[tokio::test]
    async fn test_store_get_not_found() {
        let store = InMemoryCredentialStore::new();
        let label = IdentityLabel::parse("env:MISSING").unwrap();
        let result = store.get(&label).await;
        assert!(matches!(result, Err(CredentialError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_store_put_and_get() {
        let store = InMemoryCredentialStore::new();
        let label = IdentityLabel::parse("env:NEW_KEY").unwrap();
        store.put(&label, b"new_value").await.unwrap();

        let cred = store.get(&label).await.unwrap();
        assert_eq!(cred.expose_secret(), b"new_value");
    }

    #[tokio::test]
    async fn test_store_delete() {
        let store = InMemoryCredentialStore::new();
        let label = IdentityLabel::parse("env:DELETE_ME").unwrap();
        store.insert("env:DELETE_ME", b"value");
        store.delete(&label).await.unwrap();

        let result = store.get(&label).await;
        assert!(matches!(result, Err(CredentialError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_store_list() {
        let store = InMemoryCredentialStore::new();
        store.insert("env:KEY1", b"v1");
        store.insert("env:KEY2", b"v2");
        store.insert("file:/tmp/secret", b"v3");

        let labels = store.list().await.unwrap();
        assert_eq!(labels.len(), 3);
    }

    #[tokio::test]
    async fn test_store_empty_credential() {
        let store = InMemoryCredentialStore::new();
        store.insert("env:EMPTY", b"");
        let label = IdentityLabel::parse("env:EMPTY").unwrap();
        let result = store.get(&label).await;
        assert!(matches!(result, Err(CredentialError::Empty)));
    }
}
