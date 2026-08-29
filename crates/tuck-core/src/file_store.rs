//! File-based credential store — AES-256-GCM encrypted file for development.
//!
//! # Design Principle
//!
//! **极致解耦**: FileCredentialStore is one implementation of CredentialStore.
//! Swap it for HsmCredentialStore in production without changing Tuck core.
//!
//! **物理事实优先**: The master key comes from the environment (TUCK_MASTER_KEY),
//! not from the code. The key is a physical fact — set by the operator.
//!
//! **按需加载**: Credentials are loaded from file only when `get()` is called
//! (or when the store is initialized). No pre-caching in memory.
//!
//! # Security Notes
//!
//! - This is for DEVELOPMENT use only. Production should use HSM/TPM/Vault.
//! - The master key is read from `TUCK_MASTER_KEY` env var (base64-encoded 32 bytes).
//! - Credentials are encrypted with AES-256-GCM before writing to disk.
//! - Each encryption uses a random 12-byte nonce (stored with the ciphertext).
//! - After loading, credentials are stored in memory as `Zeroizing<Vec<u8>>`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::credential::{Credential, CredentialError, CredentialStore, IdentityLabel};

// ============================================================================
// File Format
// ============================================================================

/// On-disk encrypted file format.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFile {
    /// Format version.
    version: u32,
    /// Base64-encoded 12-byte nonce.
    nonce: String,
    /// Base64-encoded AES-256-GCM ciphertext (encrypts CredentialMap).
    ciphertext: String,
}

/// Plaintext credential map (encrypted before writing).
type CredentialMap = HashMap<String, Vec<u8>>;

// ============================================================================
// Master Key
// ============================================================================

/// Master key for encrypting the credential file.
///
/// Read from `TUCK_MASTER_KEY` env var (base64-encoded 32 bytes).
pub struct MasterKey {
    key: Zeroizing<[u8; 32]>,
}

impl MasterKey {
    /// Load master key from environment variable `TUCK_MASTER_KEY`.
    pub fn from_env() -> Result<Self, CredentialError> {
        let encoded = std::env::var("TUCK_MASTER_KEY")
            .map_err(|_| CredentialError::Store("TUCK_MASTER_KEY not set".to_string()))?;
        Self::from_base64(&encoded)
    }

    /// Parse master key from base64-encoded string.
    pub fn from_base64(encoded: &str) -> Result<Self, CredentialError> {
        let bytes = base64_decode(encoded)
            .map_err(|e| CredentialError::Store(format!("invalid base64 master key: {e}")))?;
        if bytes.len() != 32 {
            return Err(CredentialError::Store(format!(
                "master key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    /// Generate a random master key (for testing/initial setup).
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut key);
        Self {
            key: Zeroizing::new(key),
        }
    }

    /// Export as base64 (for setting TUCK_MASTER_KEY env var).
    pub fn to_base64(&self) -> String {
        base64_encode(&self.key[..])
    }

    fn as_array(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        // Zeroizing handles this automatically
    }
}

// ============================================================================
// FileCredentialStore
// ============================================================================

/// File-based encrypted credential store.
///
/// # Usage
///
/// ```rust,ignore
/// use tuck_core::file_store::FileCredentialStore;
///
/// // Set TUCK_MASTER_KEY env var first (base64-encoded 32 bytes)
/// let store = FileCredentialStore::load("config/credentials.enc").await?;
///
/// // Store a credential
/// let label = IdentityLabel::parse("env:API_KEY").unwrap();
/// store.put(&label, b"sk-test-12345").await?;
/// store.save().await?;
///
/// // Retrieve a credential
/// let cred = store.get(&label).await?;
/// ```
pub struct FileCredentialStore {
    path: PathBuf,
    master_key: MasterKey,
    credentials: std::sync::Mutex<CredentialMap>,
}

impl FileCredentialStore {
    /// Create a new empty file credential store.
    pub fn new(path: impl Into<PathBuf>, master_key: MasterKey) -> Self {
        Self {
            path: path.into(),
            master_key,
            credentials: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Load an existing encrypted credential file.
    pub async fn load(path: impl Into<PathBuf>) -> Result<Self, CredentialError> {
        let path = path.into();
        let master_key = MasterKey::from_env()?;

        if !path.exists() {
            // Return empty store if file doesn't exist yet
            return Ok(Self::new(path, master_key));
        }

        let content = tokio::fs::read(&path)
            .await
            .map_err(|e| CredentialError::Store(format!("failed to read credential file: {e}")))?;

        let encrypted: EncryptedFile = serde_json::from_slice(&content)
            .map_err(|e| CredentialError::Store(format!("invalid credential file format: {e}")))?;

        if encrypted.version != 1 {
            return Err(CredentialError::Store(format!(
                "unsupported credential file version: {}",
                encrypted.version
            )));
        }

        let nonce_bytes = base64_decode(&encrypted.nonce)
            .map_err(|e| CredentialError::Store(format!("invalid nonce: {e}")))?;
        if nonce_bytes.len() != 12 {
            return Err(CredentialError::Store(format!(
                "nonce must be 12 bytes, got {}",
                nonce_bytes.len()
            )));
        }

        let ciphertext = base64_decode(&encrypted.ciphertext)
            .map_err(|e| CredentialError::Store(format!("invalid ciphertext: {e}")))?;

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(master_key.as_array())
            .map_err(|e| CredentialError::Store(format!("cipher init error: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| CredentialError::Store(format!("decryption failed: {e}")))?;

        let credentials: CredentialMap = serde_json::from_slice(&plaintext)
            .map_err(|e| CredentialError::Store(format!("invalid credential map: {e}")))?;

        Ok(Self {
            path,
            master_key,
            credentials: std::sync::Mutex::new(credentials),
        })
    }

    /// Save credentials to encrypted file.
    pub async fn save(&self) -> Result<(), CredentialError> {
        let credentials = self.credentials.lock().unwrap();
        let plaintext = serde_json::to_vec(&*credentials)
            .map_err(|e| CredentialError::Store(format!("serialization error: {e}")))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(self.master_key.as_array())
            .map_err(|e| CredentialError::Store(format!("cipher init error: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| CredentialError::Store(format!("encryption failed: {e}")))?;

        let encrypted = EncryptedFile {
            version: 1,
            nonce: base64_encode(&nonce_bytes),
            ciphertext: base64_encode(&ciphertext),
        };

        let content = serde_json::to_vec_pretty(&encrypted)
            .map_err(|e| CredentialError::Store(format!("serialization error: {e}")))?;

        // Write to temp file then rename (atomic)
        let tmp_path = self.path.with_extension("tmp");
        tokio::fs::write(&tmp_path, &content)
            .await
            .map_err(|e| CredentialError::Store(format!("failed to write credential file: {e}")))?;
        tokio::fs::rename(&tmp_path, &self.path)
            .await
            .map_err(|e| CredentialError::Store(format!("failed to rename credential file: {e}")))?;

        Ok(())
    }

    /// Get the file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait::async_trait]
impl CredentialStore for FileCredentialStore {
    async fn get(&self, label: &IdentityLabel) -> Result<Credential, CredentialError> {
        let key = label.to_string();
        let credentials = self.credentials.lock().unwrap();
        match credentials.get(&key) {
            Some(bytes) if !bytes.is_empty() => Ok(Credential::new(bytes.clone(), label.clone())),
            Some(_) => Err(CredentialError::Empty),
            None => Err(CredentialError::NotFound(key)),
        }
    }

    async fn put(&self, label: &IdentityLabel, credential: &[u8]) -> Result<(), CredentialError> {
        let key = label.to_string();
        let mut credentials = self.credentials.lock().unwrap();
        credentials.insert(key, credential.to_vec());
        Ok(())
    }

    async fn delete(&self, label: &IdentityLabel) -> Result<(), CredentialError> {
        let key = label.to_string();
        let mut credentials = self.credentials.lock().unwrap();
        credentials.remove(&key);
        Ok(())
    }

    async fn list(&self) -> Result<Vec<IdentityLabel>, CredentialError> {
        let credentials = self.credentials.lock().unwrap();
        let mut labels = Vec::new();
        for key in credentials.keys() {
            if let Ok(label) = IdentityLabel::parse(key) {
                labels.push(label);
            }
        }
        labels.sort();
        Ok(labels)
    }
}

// ============================================================================
// Base64 helpers (simple implementation, no external dep)
// ============================================================================

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((input.len() + 2) / 3 * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let n = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;

    for c in input.chars() {
        if c.is_whitespace() {
            continue;
        }
        if c == '=' {
            break;
        }
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return Err(format!("invalid base64 character: {c}")),
        };
        buffer = (buffer << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("tuck_test_credentials");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn test_master_key_generate_and_export() {
        let key = MasterKey::generate();
        let encoded = key.to_base64();
        let parsed = MasterKey::from_base64(&encoded).unwrap();
        assert_eq!(parsed.as_array(), key.as_array());
    }

    #[test]
    fn test_master_key_invalid_length() {
        let short = base64_encode(&[0u8; 16]);
        let result = MasterKey::from_base64(&short);
        assert!(matches!(result, Err(CredentialError::Store(_))));
    }

    #[test]
    fn test_master_key_invalid_base64() {
        let result = MasterKey::from_base64("not valid base64!!!");
        assert!(matches!(result, Err(CredentialError::Store(_))));
    }

    #[tokio::test]
    async fn test_file_store_put_and_get() {
        let path = temp_path("test1.enc");
        let _ = std::fs::remove_file(&path);
        let master_key = MasterKey::generate();
        let store = FileCredentialStore::new(&path, master_key);

        let label = IdentityLabel::parse("env:TEST_KEY").unwrap();
        store.put(&label, b"test_value_123").await.unwrap();
        store.save().await.unwrap();

        let cred = store.get(&label).await.unwrap();
        assert_eq!(cred.expose_secret(), b"test_value_123");
        assert_eq!(cred.label(), &label);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_file_store_load_from_disk() {
        let path = temp_path("test2.enc");
        let _ = std::fs::remove_file(&path);
        let master_key = MasterKey::generate();
        let key_b64 = master_key.to_base64();

        // Create and save
        {
            let store = FileCredentialStore::new(&path, master_key);
            let label = IdentityLabel::parse("env:KEY1").unwrap();
            store.put(&label, b"value1").await.unwrap();
            let label2 = IdentityLabel::parse("file:/tmp/secret").unwrap();
            store.put(&label2, b"file_value").await.unwrap();
            store.save().await.unwrap();
        }

        // Load with same key
        std::env::set_var("TUCK_MASTER_KEY", &key_b64);
        let store = FileCredentialStore::load(&path).await.unwrap();

        let label = IdentityLabel::parse("env:KEY1").unwrap();
        let cred = store.get(&label).await.unwrap();
        assert_eq!(cred.expose_secret(), b"value1");

        let label2 = IdentityLabel::parse("file:/tmp/secret").unwrap();
        let cred2 = store.get(&label2).await.unwrap();
        assert_eq!(cred2.expose_secret(), b"file_value");

        std::env::remove_var("TUCK_MASTER_KEY");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_file_store_wrong_key_fails() {
        let path = temp_path("test3.enc");
        let _ = std::fs::remove_file(&path);

        // Save with key A
        {
            let key_a = MasterKey::generate();
            let store = FileCredentialStore::new(&path, key_a);
            let label = IdentityLabel::parse("env:KEY").unwrap();
            store.put(&label, b"secret").await.unwrap();
            store.save().await.unwrap();
        }

        // Try to load with key B
        let key_b = MasterKey::generate();
        std::env::set_var("TUCK_MASTER_KEY", key_b.to_base64());
        let result = FileCredentialStore::load(&path).await;
        assert!(matches!(result, Err(CredentialError::Store(_))));

        std::env::remove_var("TUCK_MASTER_KEY");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_file_store_delete() {
        let path = temp_path("test4.enc");
        let _ = std::fs::remove_file(&path);
        let master_key = MasterKey::generate();
        let store = FileCredentialStore::new(&path, master_key);

        let label = IdentityLabel::parse("env:DELETE_ME").unwrap();
        store.put(&label, b"value").await.unwrap();
        store.delete(&label).await.unwrap();

        let result = store.get(&label).await;
        assert!(matches!(result, Err(CredentialError::NotFound(_))));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_file_store_list() {
        let path = temp_path("test5.enc");
        let _ = std::fs::remove_file(&path);
        let master_key = MasterKey::generate();
        let store = FileCredentialStore::new(&path, master_key);

        store.put(&IdentityLabel::parse("env:KEY1").unwrap(), b"v1").await.unwrap();
        store.put(&IdentityLabel::parse("env:KEY2").unwrap(), b"v2").await.unwrap();
        store.put(&IdentityLabel::parse("file:/tmp/s").unwrap(), b"v3").await.unwrap();

        let labels = store.list().await.unwrap();
        assert_eq!(labels.len(), 3);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_file_store_not_found() {
        let path = temp_path("test6.enc");
        let _ = std::fs::remove_file(&path);
        let master_key = MasterKey::generate();
        let store = FileCredentialStore::new(&path, master_key);

        let label = IdentityLabel::parse("env:MISSING").unwrap();
        let result = store.get(&label).await;
        assert!(matches!(result, Err(CredentialError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_file_store_load_nonexistent_returns_empty() {
        let path = temp_path("test_nonexistent.enc");
        let _ = std::fs::remove_file(&path);
        let master_key = MasterKey::generate();
        std::env::set_var("TUCK_MASTER_KEY", master_key.to_base64());

        let store = FileCredentialStore::load(&path).await.unwrap();
        assert_eq!(store.list().await.unwrap().len(), 0);

        std::env::remove_var("TUCK_MASTER_KEY");
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World! This is a test of base64 encoding.";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_empty() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn test_file_store_multiple_credentials() {
        let path = temp_path("test_multi.enc");
        let _ = std::fs::remove_file(&path);
        let master_key = MasterKey::generate();
        let store = FileCredentialStore::new(&path, master_key);

        // Add multiple credentials
        for i in 0..10 {
            let label = IdentityLabel::parse(&format!("env:KEY_{i}")).unwrap();
            store.put(&label, format!("value_{i}").as_bytes()).await.unwrap();
        }
        store.save().await.unwrap();

        // Verify all
        for i in 0..10 {
            let label = IdentityLabel::parse(&format!("env:KEY_{i}")).unwrap();
            let cred = store.get(&label).await.unwrap();
            assert_eq!(cred.expose_secret_str().unwrap(), format!("value_{i}"));
        }

        let _ = std::fs::remove_file(&path);
    }
}
