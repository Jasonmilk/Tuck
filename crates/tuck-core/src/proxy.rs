//! HTTP interceptor — extract PFP from request headers and execute decide().
//!
//! # Design Principle
//!
//! **极致解耦**: The HTTP interceptor is framework-agnostic. It works with
//! any HTTP library (axum, actix, hyper, reqwest) by operating on generic
//! header maps. No hard dependency on a specific web framework.
//!
//! **极致节能**: PFP extraction is a simple header lookup + base64 decode.
//! No body parsing, no streaming, no allocation beyond the 4-byte PFP.
//!
//! **物理事实优先**: The PFP is carried in the `X-PFP` request header
//! (base64-encoded 4 bytes). This is a physical fact — the caller must
//! provide it. Tuck never invents or guesses the PFP.
//!
//! # Header Format
//!
//! ```text
//! X-PFP: <base64-encoded 4 bytes>
//! ```
//!
//! Example: `X-PFP: zxQAAQ==` (magic 0xCF14 + features + flags)
//!
//! # Decision Mapping
//!
//! | Decision | HTTP Response |
//! |----------|---------------|
//! | Pass | Continue to next service |
//! | Reject | 403 Forbidden |
//! | NeedHumanConfirm | 401 Unauthorized (pending confirmation) |
//! | HardOverridePass | Continue (emergency override, logged) |

use serde::{Deserialize, Serialize};

use crate::{Decision, SecurityPolicy};
use crate::frame::PFP_SIZE;

// ============================================================================
// Constants
// ============================================================================

/// HTTP header name for PFP (base64-encoded 4 bytes).
pub const PFP_HEADER: &str = "x-pfp";

/// HTTP header name for Tuck decision result (for downstream services).
pub const DECISION_HEADER: &str = "x-tuck-decision";

/// HTTP header name for Tuck trace ID (for audit correlation).
pub const TRACE_HEADER: &str = "x-tuck-trace-id";

// ============================================================================
// Types
// ============================================================================

/// Intercept result — what to do with the HTTP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterceptResult {
    /// Allow the request to proceed.
    Allow,
    /// Reject the request with HTTP status.
    Reject {
        /// HTTP status code.
        status: u16,
        /// Rejection reason.
        reason: String,
    },
    /// Request needs human confirmation (pending).
    NeedConfirmation {
        /// Confirmation request ID (for HITL gate).
        request_id: String,
        /// HTTP status code (typically 401).
        status: u16,
    },
    /// Emergency override — allow with audit logging.
    HardOverride {
        /// Override reason.
        reason: String,
    },
}

/// Intercept error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum InterceptError {
    /// PFP header is missing.
    #[error("PFP header missing")]
    MissingPfp,

    /// PFP header is invalid (not base64 or wrong length).
    #[error("invalid PFP header: {0}")]
    InvalidPfp(String),

    /// PFP magic is invalid.
    #[error("invalid PFP magic: expected 0xCF14")]
    InvalidMagic,
}

// ============================================================================
// HTTP Interceptor
// ============================================================================

/// HTTP request interceptor — extract PFP from headers and execute decide().
///
/// # Usage
///
/// ```rust,ignore
/// use tuck_core::proxy::HttpInterceptor;
/// use tuck_core::SecurityPolicy;
///
/// let policy = SecurityPolicy::default();
/// let interceptor = HttpInterceptor::new(policy);
///
/// // Extract PFP from headers and decide
/// let headers = vec![("x-pfp", "zxQAAQ==")];
/// let result = interceptor.intercept(&headers).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct HttpInterceptor {
    policy: SecurityPolicy,
}

impl HttpInterceptor {
    /// Create a new HTTP interceptor with the given security policy.
    pub fn new(policy: SecurityPolicy) -> Self {
        Self { policy }
    }

    /// Intercept an HTTP request — extract PFP from headers and execute decide().
    ///
    /// `headers` is an iterator of (name, value) pairs. Names are
    /// case-insensitive.
    pub fn intercept<'a, I>(&self, headers: I) -> Result<InterceptResult, InterceptError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        // Extract PFP from headers
        let pfp_bytes = self.extract_pfp(headers)?;

        // Convert to PfpHeader for decide()
        let pfp = crate::PfpHeader::from_bytes(pfp_bytes)
            .map_err(|e| InterceptError::InvalidPfp(format!("PFP validation failed: {e}")))?;

        // Execute decide()
        let decision = crate::decide(&pfp, &self.policy);

        // Map decision to intercept result
        Ok(self.map_decision(decision))
    }

    /// Extract PFP 4 bytes from request headers.
    ///
    /// Looks for the `X-PFP` header (case-insensitive), base64-decodes it,
    /// and validates the length (must be exactly 4 bytes) and magic (0xCF14).
    pub fn extract_pfp<'a, I>(&self, headers: I) -> Result<[u8; PFP_SIZE], InterceptError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        // Find PFP header (case-insensitive)
        let pfp_header = headers
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(PFP_HEADER))
            .map(|(_, value)| value)
            .ok_or(InterceptError::MissingPfp)?;

        // Base64 decode
        let decoded = base64_decode(pfp_header)
            .map_err(|e| InterceptError::InvalidPfp(format!("base64 decode failed: {e}")))?;

        // Validate length
        if decoded.len() != PFP_SIZE {
            return Err(InterceptError::InvalidPfp(format!(
                "expected {} bytes, got {}",
                PFP_SIZE,
                decoded.len()
            )));
        }

        // Validate magic (first 2 bytes should be 0xCF14)
        if decoded[0] != 0xCF || decoded[1] != 0x14 {
            return Err(InterceptError::InvalidMagic);
        }

        let mut pfp = [0u8; PFP_SIZE];
        pfp.copy_from_slice(&decoded);
        Ok(pfp)
    }

    /// Map a Decision to an InterceptResult.
    fn map_decision(&self, decision: Decision) -> InterceptResult {
        match decision {
            Decision::Pass => InterceptResult::Allow,
            Decision::Reject => InterceptResult::Reject {
                status: 403,
                reason: "Tuck security policy rejected the request".to_string(),
            },
            Decision::NeedHumanConfirm => InterceptResult::NeedConfirmation {
                request_id: uuid::Uuid::new_v4().to_string(),
                status: 401,
            },
            Decision::HardOverridePass => InterceptResult::HardOverride {
                reason: "CATASTROPHIC risk with hard override flag — emergency pass".to_string(),
            },
        }
    }

    /// Get the security policy.
    pub fn policy(&self) -> &SecurityPolicy {
        &self.policy
    }
}

// ============================================================================
// Header helpers
// ============================================================================

/// Create a PFP header value from PFP bytes (base64-encoded).
pub fn pfp_header_value(pfp: &[u8; PFP_SIZE]) -> String {
    base64_encode(pfp)
}

/// Create a full PFP header (name: value).
pub fn pfp_header(pfp: &[u8; PFP_SIZE]) -> (String, String) {
    (PFP_HEADER.to_string(), pfp_header_value(pfp))
}

// ============================================================================
// Base64 helpers (simple implementation)
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
    use crate::{Modality, OverrideFlag, RiskLevel};

    /// Build a PFP 4-byte array from risk level and override flag.
    ///
    /// PFP layout:
    /// - bytes 0-1: magic 0xCF14
    /// - byte 2: Modality(2) + RiskLevel(2) + BodyStance(2) + ProximityEdge(2)
    /// - byte 3: OutputDest(1) + OverrideFlag(1) + ReplayEnable(1) + Reserved(5)
    fn make_pfp(risk: RiskLevel, override_flag: OverrideFlag) -> [u8; 4] {
        let modality = Modality::Executive as u8; // 2
        let body_stance = 1; // Standing
        let proximity_edge = 0; // Safe
        let output_dest = 1; // External
        let replay_enable = 1; // Enabled

        let byte2 = modality | (risk as u8) << 2 | body_stance << 4 | proximity_edge << 6;
        let byte3 = output_dest | (override_flag as u8) << 1 | replay_enable << 2;

        [0xCF, 0x14, byte2, byte3]
    }

    #[test]
    fn test_pfp_header_value_roundtrip() {
        let pfp = make_pfp(RiskLevel::Low, OverrideFlag::Normal);
        let header_value = pfp_header_value(&pfp);
        let decoded = base64_decode(&header_value).unwrap();
        assert_eq!(decoded, pfp.to_vec());
    }

    #[test]
    fn test_intercept_allow() {
        let policy = SecurityPolicy::default();
        let interceptor = HttpInterceptor::new(policy);

        let pfp = make_pfp(RiskLevel::Low, OverrideFlag::Normal);
        let header_value = pfp_header_value(&pfp);
        let headers = vec![(PFP_HEADER, header_value.as_str())];

        let result = interceptor.intercept(headers).unwrap();
        assert_eq!(result, InterceptResult::Allow);
    }

    #[test]
    fn test_intercept_reject() {
        let policy = SecurityPolicy::default();
        let interceptor = HttpInterceptor::new(policy);

        // Catastrophic without override → Reject
        let pfp = make_pfp(RiskLevel::Catastrophic, OverrideFlag::Normal);
        let header_value = pfp_header_value(&pfp);
        let headers = vec![(PFP_HEADER, header_value.as_str())];

        let result = interceptor.intercept(headers).unwrap();
        match result {
            InterceptResult::Reject { status, .. } => assert_eq!(status, 403),
            _ => panic!("expected Reject"),
        }
    }

    #[test]
    fn test_intercept_hard_override() {
        let policy = SecurityPolicy::default();
        let interceptor = HttpInterceptor::new(policy);

        // Catastrophic with override → HardOverridePass
        let pfp = make_pfp(RiskLevel::Catastrophic, OverrideFlag::HardOverride);
        let header_value = pfp_header_value(&pfp);
        let headers = vec![(PFP_HEADER, header_value.as_str())];

        let result = interceptor.intercept(headers).unwrap();
        match result {
            InterceptResult::HardOverride { .. } => {}
            _ => panic!("expected HardOverride"),
        }
    }

    #[test]
    fn test_intercept_need_human_confirm() {
        let mut policy = SecurityPolicy::default();
        // Set Critical to NeedHumanConfirm
        policy = SecurityPolicy {
            critical: Decision::NeedHumanConfirm,
            ..policy
        };
        let interceptor = HttpInterceptor::new(policy);

        let pfp = make_pfp(RiskLevel::Critical, OverrideFlag::Normal);
        let header_value = pfp_header_value(&pfp);
        let headers = vec![(PFP_HEADER, header_value.as_str())];

        let result = interceptor.intercept(headers).unwrap();
        match result {
            InterceptResult::NeedConfirmation { status, .. } => assert_eq!(status, 401),
            _ => panic!("expected NeedConfirmation"),
        }
    }

    #[test]
    fn test_intercept_missing_pfp() {
        let policy = SecurityPolicy::default();
        let interceptor = HttpInterceptor::new(policy);

        let headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];
        let result = interceptor.intercept(headers);
        assert!(matches!(result, Err(InterceptError::MissingPfp)));
    }

    #[test]
    fn test_intercept_invalid_pfp_length() {
        let policy = SecurityPolicy::default();
        let interceptor = HttpInterceptor::new(policy);

        // Only 2 bytes after base64 decode
        let headers = vec![(PFP_HEADER, "zxA=")]; // decodes to 2 bytes
        let result = interceptor.intercept(headers);
        assert!(matches!(result, Err(InterceptError::InvalidPfp(_))));
    }

    #[test]
    fn test_intercept_invalid_pfp_magic() {
        let policy = SecurityPolicy::default();
        let interceptor = HttpInterceptor::new(policy);

        // 4 bytes but wrong magic (0x0000 instead of 0xCF14)
        let headers = vec![(PFP_HEADER, "AAAAAA==")]; // decodes to [0,0,0,0]
        let result = interceptor.intercept(headers);
        assert!(matches!(result, Err(InterceptError::InvalidMagic)));
    }

    #[test]
    fn test_intercept_case_insensitive_header() {
        let policy = SecurityPolicy::default();
        let interceptor = HttpInterceptor::new(policy);

        let pfp = make_pfp(RiskLevel::Low, OverrideFlag::Normal);
        let header_value = pfp_header_value(&pfp);
        // Use uppercase header name
        let headers = vec![("X-PFP", header_value.as_str())];

        let result = interceptor.intercept(headers).unwrap();
        assert_eq!(result, InterceptResult::Allow);
    }

    #[test]
    fn test_extract_pfp_valid() {
        let policy = SecurityPolicy::default();
        let interceptor = HttpInterceptor::new(policy);

        let pfp = make_pfp(RiskLevel::Medium, OverrideFlag::Normal);
        let header_value = pfp_header_value(&pfp);
        let headers = vec![(PFP_HEADER, header_value.as_str())];

        let extracted = interceptor.extract_pfp(headers).unwrap();
        assert_eq!(extracted, pfp);
    }

    #[test]
    fn test_pfp_header_creation() {
        let pfp = make_pfp(RiskLevel::Low, OverrideFlag::Normal);
        let (name, value) = pfp_header(&pfp);
        assert_eq!(name, PFP_HEADER);
        assert!(!value.is_empty());
    }

    #[test]
    fn test_intercept_result_serialization() {
        let result = InterceptResult::Reject {
            status: 403,
            reason: "test".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: InterceptResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, result);
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = [0xCF, 0x14, 0xAB, 0xCD];
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_interceptor_policy_access() {
        let policy = SecurityPolicy::default();
        let interceptor = HttpInterceptor::new(policy);
        // Verify policy is accessible (SecurityPolicy doesn't impl PartialEq)
        let _ = interceptor.policy();
    }
}
