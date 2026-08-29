//! Physical edge credential injection — inject credentials at the outbound boundary,
//! then immediately zeroize.
//!
//! # Design Principle
//!
//! **凭证永不在组件内存中** (Core Promise #3):
//! - Credentials are resolved from `CredentialStore` ONLY at the physical edge
//! - After injection into the outbound request, the `Credential` is dropped
//!   immediately, triggering `zeroize`
//! - The plaintext credential exists in memory for the minimum possible time
//!
//! **物理事实优先**: Injection happens at the network boundary — the last
//! point before bytes leave the process. This is the only place where
//! plaintext credentials are needed.
//!
//! **极致解耦**: Injection targets are enum-driven — add new targets without
//! changing the core injection logic.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::credential::{Credential, CredentialError, CredentialStore, IdentityLabel};

// ============================================================================
// Injection Target
// ============================================================================

/// Where to inject the credential in the outbound request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InjectionTarget {
    /// HTTP header: `Header-Name: credential_value`
    HttpHeader {
        /// Header name (case-insensitive).
        name: String,
    },
    /// Bearer token in Authorization header: `Authorization: Bearer <credential>`
    BearerToken,
    /// Query parameter: `?param_name=credential_value`
    QueryParam {
        /// Query parameter name.
        name: String,
    },
    /// JSON body field: `{"field_name": "credential_value"}`
    BodyField {
        /// JSON field name (dot-path supported, e.g., "auth.token").
        path: String,
    },
    /// Basic auth: `Authorization: Basic base64(username:credential)`
    BasicAuth {
        /// Username for basic auth.
        username: String,
    },
}

impl InjectionTarget {
    /// Create an HTTP header injection target.
    pub fn header(name: impl Into<String>) -> Self {
        Self::HttpHeader { name: name.into() }
    }

    /// Create a query parameter injection target.
    pub fn query_param(name: impl Into<String>) -> Self {
        Self::QueryParam { name: name.into() }
    }

    /// Create a JSON body field injection target.
    pub fn body_field(path: impl Into<String>) -> Self {
        Self::BodyField { path: path.into() }
    }
}

// ============================================================================
// Outbound Request (simplified model)
// ============================================================================

/// A simplified outbound request model for credential injection.
///
/// In production, this would be replaced by the actual HTTP client request
/// type (e.g., `reqwest::Request`). This struct provides a testable model.
#[derive(Debug, Clone, Default)]
pub struct OutboundRequest {
    /// HTTP headers (name → value).
    pub headers: HashMap<String, String>,
    /// Query parameters (name → value).
    pub query_params: HashMap<String, String>,
    /// Request body (raw bytes, typically JSON).
    pub body: Option<Vec<u8>>,
}

impl OutboundRequest {
    /// Create a new empty outbound request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an HTTP header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Set a query parameter.
    pub fn with_query_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_params.insert(name.into(), value.into());
        self
    }

    /// Set the request body.
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Get a header value (case-insensitive).
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }
}

// ============================================================================
// Injection Result
// ============================================================================

/// Result of a credential injection operation.
#[derive(Debug, Clone)]
pub struct InjectionResult {
    /// The identity_label that was resolved.
    pub label: IdentityLabel,
    /// The injection target that was used.
    pub target: InjectionTarget,
    /// Whether the injection was successful.
    pub success: bool,
    /// The credential length (for audit — never the actual secret).
    pub credential_len: usize,
    /// Error message if injection failed.
    pub error: Option<String>,
}

// ============================================================================
// Injection Engine
// ============================================================================

/// Credential injection engine — resolves identity_label → credential → injects
/// into outbound request → zeroizes credential.
///
/// # Usage
///
/// ```rust,ignore
/// use tuck_core::injection::{InjectionEngine, InjectionTarget, OutboundRequest};
/// use tuck_core::credential::IdentityLabel;
///
/// let engine = InjectionEngine::new(credential_store);
/// let label = IdentityLabel::parse("env:API_KEY").unwrap();
/// let target = InjectionTarget::header("X-API-Key");
///
/// let mut request = OutboundRequest::new();
/// let result = engine.inject(&label, &target, &mut request).await.unwrap();
/// // request now has X-API-Key header, credential is zeroized
/// ```
#[derive(Clone)]
pub struct InjectionEngine<S: CredentialStore> {
    store: S,
}

impl<S: CredentialStore> InjectionEngine<S> {
    /// Create a new injection engine with the given credential store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Inject a credential into an outbound request.
    ///
    /// # Flow
    ///
    /// 1. Resolve `identity_label` → `Credential` from store
    /// 2. Inject credential bytes into the request at `target`
    /// 3. Drop `Credential` (triggers zeroize)
    /// 4. Return `InjectionResult`
    ///
    /// The plaintext credential exists in memory only during step 2.
    pub async fn inject(
        &self,
        label: &IdentityLabel,
        target: &InjectionTarget,
        request: &mut OutboundRequest,
    ) -> Result<InjectionResult, CredentialError> {
        // Step 1: Resolve credential from store
        let credential = self.store.get(label).await?;
        let cred_len = credential.len();

        // Step 2: Inject into request (credential is alive only in this scope)
        let inject_result = self.inject_into_request(&credential, target, request);

        // Step 3: Credential is dropped here → zeroize triggered automatically
        // (credential goes out of scope at end of function)

        match inject_result {
            Ok(()) => Ok(InjectionResult {
                label: label.clone(),
                target: target.clone(),
                success: true,
                credential_len: cred_len,
                error: None,
            }),
            Err(e) => Ok(InjectionResult {
                label: label.clone(),
                target: target.clone(),
                success: false,
                credential_len: cred_len,
                error: Some(e),
            }),
        }
    }

    /// Inject credential bytes into the request at the target location.
    fn inject_into_request(
        &self,
        credential: &Credential,
        target: &InjectionTarget,
        request: &mut OutboundRequest,
    ) -> Result<(), String> {
        let secret = credential.expose_secret();

        match target {
            InjectionTarget::HttpHeader { name } => {
                let value = String::from_utf8(secret.to_vec())
                    .map_err(|e| format!("invalid UTF-8 in credential: {e}"))?;
                request.headers.insert(name.clone(), value);
            }
            InjectionTarget::BearerToken => {
                let token = String::from_utf8(secret.to_vec())
                    .map_err(|e| format!("invalid UTF-8 in credential: {e}"))?;
                request
                    .headers
                    .insert("Authorization".to_string(), format!("Bearer {token}"));
            }
            InjectionTarget::QueryParam { name } => {
                let value = String::from_utf8(secret.to_vec())
                    .map_err(|e| format!("invalid UTF-8 in credential: {e}"))?;
                request.query_params.insert(name.clone(), value);
            }
            InjectionTarget::BodyField { path } => {
                self.inject_body_field(secret, path, request)?;
            }
            InjectionTarget::BasicAuth { username } => {
                let password = String::from_utf8(secret.to_vec())
                    .map_err(|e| format!("invalid UTF-8 in credential: {e}"))?;
                let combined = format!("{username}:{password}");
                let encoded = base64_encode(combined.as_bytes());
                request
                    .headers
                    .insert("Authorization".to_string(), format!("Basic {encoded}"));
            }
        }

        Ok(())
    }

    /// Inject credential into a JSON body field (simple dot-path implementation).
    fn inject_body_field(
        &self,
        secret: &[u8],
        path: &str,
        request: &mut OutboundRequest,
    ) -> Result<(), String> {
        let value = String::from_utf8(secret.to_vec())
            .map_err(|e| format!("invalid UTF-8 in credential: {e}"))?;

        // Parse existing body or create new JSON object
        let mut json: serde_json::Value = match &request.body {
            Some(bytes) => serde_json::from_slice(bytes)
                .map_err(|e| format!("invalid JSON body: {e}"))?,
            None => serde_json::Value::Object(serde_json::Map::new()),
        };

        // Navigate dot-path and set value
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = &mut json;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                current[part] = serde_json::Value::String(value.clone());
            } else {
                if current.get(part).is_none() {
                    current[part] = serde_json::Value::Object(serde_json::Map::new());
                }
                current = current.get_mut(part).unwrap();
            }
        }

        // Serialize back to body
        let body = serde_json::to_vec(&json).map_err(|e| format!("JSON serialization error: {e}"))?;
        request.body = Some(body);

        Ok(())
    }
}

// ============================================================================
// Helper: simple base64 encode (no external dep for this simple use)
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::InMemoryCredentialStore;

    fn setup_store() -> InMemoryCredentialStore {
        let store = InMemoryCredentialStore::new();
        store.insert("env:API_KEY", b"sk-test-12345");
        store.insert("env:BEARER_TOKEN", b"eyJhbGciOiJIUzI1NiJ9.test");
        store.insert("env:DB_PASSWORD", b"super_secret_pw");
        store.insert("file:/tmp/secret", b"file-based-secret");
        store
    }

    #[tokio::test]
    async fn test_inject_http_header() {
        let store = setup_store();
        let engine = InjectionEngine::new(store);
        let label = IdentityLabel::parse("env:API_KEY").unwrap();
        let target = InjectionTarget::header("X-API-Key");

        let mut request = OutboundRequest::new();
        let result = engine.inject(&label, &target, &mut request).await.unwrap();

        assert!(result.success);
        assert_eq!(result.credential_len, 13);
        assert_eq!(request.get_header("X-API-Key").unwrap(), "sk-test-12345");
    }

    #[tokio::test]
    async fn test_inject_bearer_token() {
        let store = setup_store();
        let engine = InjectionEngine::new(store);
        let label = IdentityLabel::parse("env:BEARER_TOKEN").unwrap();
        let target = InjectionTarget::BearerToken;

        let mut request = OutboundRequest::new();
        let result = engine.inject(&label, &target, &mut request).await.unwrap();

        assert!(result.success);
        let auth = request.get_header("Authorization").unwrap();
        assert!(auth.starts_with("Bearer "));
        assert!(auth.contains("eyJhbGciOiJIUzI1NiJ9.test"));
    }

    #[tokio::test]
    async fn test_inject_query_param() {
        let store = setup_store();
        let engine = InjectionEngine::new(store);
        let label = IdentityLabel::parse("env:API_KEY").unwrap();
        let target = InjectionTarget::query_param("api_key");

        let mut request = OutboundRequest::new();
        let result = engine.inject(&label, &target, &mut request).await.unwrap();

        assert!(result.success);
        assert_eq!(request.query_params.get("api_key").unwrap(), "sk-test-12345");
    }

    #[tokio::test]
    async fn test_inject_body_field() {
        let store = setup_store();
        let engine = InjectionEngine::new(store);
        let label = IdentityLabel::parse("env:DB_PASSWORD").unwrap();
        let target = InjectionTarget::body_field("database.password");

        let mut request = OutboundRequest::new().with_body(br#"{"database":{"host":"localhost"}}"#.to_vec());
        let result = engine.inject(&label, &target, &mut request).await.unwrap();

        assert!(result.success);
        let body = request.body.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["database"]["password"], "super_secret_pw");
        assert_eq!(json["database"]["host"], "localhost");
    }

    #[tokio::test]
    async fn test_inject_body_field_new_body() {
        let store = setup_store();
        let engine = InjectionEngine::new(store);
        let label = IdentityLabel::parse("env:API_KEY").unwrap();
        let target = InjectionTarget::body_field("auth.api_key");

        let mut request = OutboundRequest::new(); // no body
        let result = engine.inject(&label, &target, &mut request).await.unwrap();

        assert!(result.success);
        let body = request.body.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["auth"]["api_key"], "sk-test-12345");
    }

    #[tokio::test]
    async fn test_inject_basic_auth() {
        let store = setup_store();
        let engine = InjectionEngine::new(store);
        let label = IdentityLabel::parse("env:DB_PASSWORD").unwrap();
        let target = InjectionTarget::BasicAuth { username: "admin".to_string() };

        let mut request = OutboundRequest::new();
        let result = engine.inject(&label, &target, &mut request).await.unwrap();

        assert!(result.success);
        let auth = request.get_header("Authorization").unwrap();
        assert!(auth.starts_with("Basic "));
        // Verify base64 decode: "admin:super_secret_pw"
        let encoded = auth.strip_prefix("Basic ").unwrap();
        let decoded = base64_decode(encoded);
        assert_eq!(decoded, b"admin:super_secret_pw");
    }

    #[tokio::test]
    async fn test_inject_credential_not_found() {
        let store = setup_store();
        let engine = InjectionEngine::new(store);
        let label = IdentityLabel::parse("env:MISSING").unwrap();
        let target = InjectionTarget::header("X-Key");

        let mut request = OutboundRequest::new();
        let result = engine.inject(&label, &target, &mut request).await;

        assert!(matches!(result, Err(CredentialError::NotFound(_))));
        assert!(request.headers.is_empty());
    }

    #[tokio::test]
    async fn test_inject_file_credential() {
        let store = setup_store();
        let engine = InjectionEngine::new(store);
        let label = IdentityLabel::parse("file:/tmp/secret").unwrap();
        let target = InjectionTarget::header("X-File-Secret");

        let mut request = OutboundRequest::new();
        let result = engine.inject(&label, &target, &mut request).await.unwrap();

        assert!(result.success);
        assert_eq!(request.get_header("X-File-Secret").unwrap(), "file-based-secret");
    }

    #[tokio::test]
    async fn test_injection_result_metadata() {
        let store = setup_store();
        let engine = InjectionEngine::new(store);
        let label = IdentityLabel::parse("env:API_KEY").unwrap();
        let target = InjectionTarget::header("X-Key");

        let mut request = OutboundRequest::new();
        let result = engine.inject(&label, &target, &mut request).await.unwrap();

        assert_eq!(result.label, label);
        assert_eq!(result.target, target);
        assert!(result.success);
        assert_eq!(result.credential_len, 13);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_credential_zeroized_after_injection() {
        // This test verifies that the credential is dropped after injection.
        // We can't directly inspect zeroized memory, but we can verify that
        // the InjectionResult only contains metadata (length, not the secret).
        let store = setup_store();
        let engine = InjectionEngine::new(store);
        let label = IdentityLabel::parse("env:API_KEY").unwrap();
        let target = InjectionTarget::header("X-Key");

        let mut request = OutboundRequest::new();
        let result = engine.inject(&label, &target, &mut request).await.unwrap();

        // Result contains only metadata, never the secret
        let result_debug = format!("{:?}", result);
        assert!(!result_debug.contains("sk-test-12345"));

        // The credential was injected into the request (this is expected at the edge)
        assert_eq!(request.get_header("X-Key").unwrap(), "sk-test-12345");
        // After the request is sent, the caller should zeroize the request too
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"admin:password"), "YWRtaW46cGFzc3dvcmQ=");
    }

    fn base64_decode(input: &str) -> Vec<u8> {
        let mut result = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0;

        for c in input.chars() {
            if c == '=' {
                break;
            }
            let val = match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                'a'..='z' => c as u32 - 'a' as u32 + 26,
                '0'..='9' => c as u32 - '0' as u32 + 52,
                '+' => 62,
                '/' => 63,
                _ => continue,
            };
            buffer = (buffer << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                result.push((buffer >> bits) as u8);
                buffer &= (1 << bits) - 1;
            }
        }
        result
    }
}
