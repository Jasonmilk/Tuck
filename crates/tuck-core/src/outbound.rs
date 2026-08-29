//! Outbound request handler — integrate HTTP interception with credential injection.
//!
//! # Design Principle
//!
//! **极致解耦**: The outbound handler composes two independent components:
//! `HttpInterceptor` (security decision) and `InjectionEngine` (credential
//! injection). Neither knows about the other — the handler orchestrates them.
//!
//! **按需驱动**: Credential injection only happens when the request is
//! `Allow`ed. Rejected requests never touch the credential store.
//!
//! **物理事实优先**: The `identity_label` is carried in the request header
//! (`X-Identity-Label`). Tuck never invents or guesses the identity.
//!
//! # Flow
//!
//! ```text
//! 1. Extract PFP from X-PFP header
//! 2. Execute decide() → Pass/Reject/NeedHumanConfirm/HardOverridePass
//! 3. If Pass or HardOverridePass:
//!    a. Extract identity_label from X-Identity-Label header
//!    b. Resolve credential from CredentialStore
//!    c. Inject credential into outbound request (header/query/body)
//!    d. Credential is zeroized after injection
//! 4. Return OutboundResult (decision + injection result)
//! ```

use serde::{Deserialize, Serialize};

use crate::credential::{CredentialError, CredentialStore, IdentityLabel};
use crate::injection::{InjectionEngine, InjectionResult, InjectionTarget, OutboundRequest};
use crate::proxy::{HttpInterceptor, InterceptError, InterceptResult};
use crate::SecurityPolicy;

// ============================================================================
// Constants
// ============================================================================

/// HTTP header name for identity label.
pub const IDENTITY_LABEL_HEADER: &str = "x-identity-label";

// ============================================================================
// Types
// ============================================================================

/// Outbound request handling result.
#[derive(Debug, Clone)]
pub struct OutboundResult {
    /// Security decision (from HttpInterceptor).
    pub decision: OutboundDecision,
    /// Credential injection result (only if decision is Allow/HardOverride).
    pub injection: Option<InjectionResult>,
    /// The outbound request (with credential injected if applicable).
    pub request: OutboundRequest,
}

/// Outbound decision (simplified from InterceptResult).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboundDecision {
    /// Request allowed, proceed with credential injection.
    Allow,
    /// Request rejected.
    Reject {
        /// HTTP status code.
        status: u16,
        /// Rejection reason.
        reason: String,
    },
    /// Request needs human confirmation.
    NeedConfirmation {
        /// Confirmation request ID.
        request_id: String,
        /// HTTP status code.
        status: u16,
    },
    /// Emergency override — allowed with audit logging.
    HardOverride {
        /// Override reason.
        reason: String,
    },
}

/// Outbound handler error.
#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    /// Interception error (PFP missing/invalid).
    #[error("interception error: {0}")]
    Interception(#[from] InterceptError),

    /// Credential error (store failure, label not found).
    #[error("credential error: {0}")]
    Credential(#[from] CredentialError),

    /// Identity label header missing.
    #[error("identity label header missing")]
    MissingIdentityLabel,
}

// ============================================================================
// Outbound Handler
// ============================================================================

/// Outbound request handler — compose HTTP interception with credential injection.
///
/// # Usage
///
/// ```rust,ignore
/// use tuck_core::outbound::OutboundHandler;
/// use tuck_core::file_store::FileCredentialStore;
/// use tuck_core::SecurityPolicy;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let policy = SecurityPolicy::default();
/// let store = FileCredentialStore::new("/tmp/tuck-credentials", "master-key-base64")?;
/// let handler = OutboundHandler::new(policy, store);
///
/// let headers = vec![
///     ("x-pfp", "zxQAAQ=="),
///     ("x-identity-label", "scheme:path/to/credential"),
/// ];
/// let mut request = OutboundRequest::new();
/// let target = InjectionTarget::header("X-API-Key");
///
/// let result = handler.handle_outbound(&headers, &mut request, &target).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct OutboundHandler<S: CredentialStore> {
    interceptor: HttpInterceptor,
    injection_engine: InjectionEngine<S>,
}

impl<S: CredentialStore> OutboundHandler<S> {
    /// Create a new outbound handler with the given policy and credential store.
    pub fn new(policy: SecurityPolicy, store: S) -> Self {
        Self {
            interceptor: HttpInterceptor::new(policy),
            injection_engine: InjectionEngine::new(store),
        }
    }

    /// Handle an outbound request — intercept, decide, and inject credentials.
    ///
    /// # Flow
    ///
    /// 1. Extract PFP from headers and execute `decide()`
    /// 2. If `Allow` or `HardOverride`:
    ///    - Extract `identity_label` from headers
    ///    - Resolve credential from store
    ///    - Inject credential into request at `target`
    ///    - Credential is zeroized after injection
    /// 3. Return `OutboundResult`
    pub async fn handle_outbound<'a, I>(
        &self,
        headers: I,
        request: &mut OutboundRequest,
        target: &InjectionTarget,
    ) -> Result<OutboundResult, OutboundError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)> + Clone,
    {
        // Step 1: Intercept and decide
        let intercept_result = self.interceptor.intercept(headers.clone())?;

        // Map to outbound decision
        let decision = match &intercept_result {
            InterceptResult::Allow => OutboundDecision::Allow,
            InterceptResult::Reject { status, reason } => OutboundDecision::Reject {
                status: *status,
                reason: reason.clone(),
            },
            InterceptResult::NeedConfirmation { request_id, status } => {
                OutboundDecision::NeedConfirmation {
                    request_id: request_id.clone(),
                    status: *status,
                }
            }
            InterceptResult::HardOverride { reason } => OutboundDecision::HardOverride {
                reason: reason.clone(),
            },
        };

        // Step 2: Inject credentials only if allowed
        let injection = match &intercept_result {
            InterceptResult::Allow | InterceptResult::HardOverride { .. } => {
                // Extract identity label from headers
                let label_str = headers
                    .clone()
                    .into_iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(IDENTITY_LABEL_HEADER))
                    .map(|(_, value)| value)
                    .ok_or(OutboundError::MissingIdentityLabel)?;

                let label = IdentityLabel::parse(label_str)?;

                // Inject credential
                let result = self
                    .injection_engine
                    .inject(&label, target, request)
                    .await?;

                Some(result)
            }
            _ => None,
        };

        Ok(OutboundResult {
            decision,
            injection,
            request: request.clone(),
        })
    }

    /// Get the security policy.
    pub fn policy(&self) -> &SecurityPolicy {
        self.interceptor.policy()
    }

    /// Get a reference to the injection engine.
    pub fn injection_engine(&self) -> &InjectionEngine<S> {
        &self.injection_engine
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::InMemoryCredentialStore;
    use crate::injection::InjectionTarget;
    use crate::{OverrideFlag, RiskLevel};

    /// Build a PFP 4-byte array from risk level and override flag.
    fn make_pfp(risk: RiskLevel, override_flag: OverrideFlag) -> [u8; 4] {
        let modality = 2; // Executive
        let body_stance = 1; // Standing
        let proximity_edge = 0; // Safe
        let output_dest = 1; // External
        let replay_enable = 1; // Enabled

        let byte2 = modality | (risk as u8) << 2 | body_stance << 4 | proximity_edge << 6;
        let byte3 = output_dest | (override_flag as u8) << 1 | replay_enable << 2;

        [0xCF, 0x14, byte2, byte3]
    }

    fn pfp_header_value(pfp: &[u8; 4]) -> String {
        crate::proxy::pfp_header_value(pfp)
    }

    #[tokio::test]
    async fn test_outbound_allow_with_injection() {
        let store = InMemoryCredentialStore::new();
        store.insert("env:test/api-key", b"secret-token-12345");

        let handler = OutboundHandler::new(SecurityPolicy::default(), store);

        let pfp = make_pfp(RiskLevel::Low, OverrideFlag::Normal);
        let pfp_value = pfp_header_value(&pfp);
        let headers = vec![
            ("x-pfp", pfp_value.as_str()),
            ("x-identity-label", "env:test/api-key"),
        ];

        let mut request = OutboundRequest::new();
        let target = InjectionTarget::header("X-API-Key");

        let result = handler
            .handle_outbound(headers, &mut request, &target)
            .await
            .unwrap();

        assert_eq!(result.decision, OutboundDecision::Allow);
        assert!(result.injection.is_some());
        assert!(result.injection.unwrap().success);
        // Verify credential was injected
        assert_eq!(
            request.get_header("X-API-Key").unwrap(),
            "secret-token-12345"
        );
    }

    #[tokio::test]
    async fn test_outbound_reject_no_injection() {
        let store = InMemoryCredentialStore::new();
        let handler = OutboundHandler::new(SecurityPolicy::default(), store);

        // Catastrophic without override → Reject
        let pfp = make_pfp(RiskLevel::Catastrophic, OverrideFlag::Normal);
        let pfp_value = pfp_header_value(&pfp);
        let headers = vec![
            ("x-pfp", pfp_value.as_str()),
            ("x-identity-label", "env:test/api-key"),
        ];

        let mut request = OutboundRequest::new();
        let target = InjectionTarget::header("X-API-Key");

        let result = handler
            .handle_outbound(headers, &mut request, &target)
            .await
            .unwrap();

        match result.decision {
            OutboundDecision::Reject { status, .. } => assert_eq!(status, 403),
            _ => panic!("expected Reject"),
        }
        // No injection for rejected requests
        assert!(result.injection.is_none());
        // No credential in request
        assert!(request.get_header("X-API-Key").is_none());
    }

    #[tokio::test]
    async fn test_outbound_hard_override_with_injection() {
        let store = InMemoryCredentialStore::new();
        store.insert("env:test/emergency", b"emergency-token");

        let handler = OutboundHandler::new(SecurityPolicy::default(), store);

        // Catastrophic with override → HardOverridePass
        let pfp = make_pfp(RiskLevel::Catastrophic, OverrideFlag::HardOverride);
        let pfp_value = pfp_header_value(&pfp);
        let headers = vec![
            ("x-pfp", pfp_value.as_str()),
            ("x-identity-label", "env:test/emergency"),
        ];

        let mut request = OutboundRequest::new();
        let target = InjectionTarget::BearerToken;

        let result = handler
            .handle_outbound(headers, &mut request, &target)
            .await
            .unwrap();

        match result.decision {
            OutboundDecision::HardOverride { .. } => {}
            _ => panic!("expected HardOverride"),
        }
        assert!(result.injection.is_some());
        // Verify Bearer token was injected
        assert_eq!(
            request.get_header("Authorization").unwrap(),
            "Bearer emergency-token"
        );
    }

    #[tokio::test]
    async fn test_outbound_missing_identity_label() {
        let store = InMemoryCredentialStore::new();
        let handler = OutboundHandler::new(SecurityPolicy::default(), store);

        let pfp = make_pfp(RiskLevel::Low, OverrideFlag::Normal);
        let pfp_value = pfp_header_value(&pfp);
        // No identity label header
        let headers = vec![("x-pfp", pfp_value.as_str())];

        let mut request = OutboundRequest::new();
        let target = InjectionTarget::header("X-API-Key");

        let result = handler
            .handle_outbound(headers, &mut request, &target)
            .await;

        assert!(matches!(result, Err(OutboundError::MissingIdentityLabel)));
    }

    #[tokio::test]
    async fn test_outbound_missing_pfp() {
        let store = InMemoryCredentialStore::new();
        let handler = OutboundHandler::new(SecurityPolicy::default(), store);

        // No PFP header
        let headers = vec![("x-identity-label", "env:test/api-key")];

        let mut request = OutboundRequest::new();
        let target = InjectionTarget::header("X-API-Key");

        let result = handler
            .handle_outbound(headers, &mut request, &target)
            .await;

        assert!(matches!(
            result,
            Err(OutboundError::Interception(InterceptError::MissingPfp))
        ));
    }

    #[tokio::test]
    async fn test_outbound_credential_not_found() {
        let store = InMemoryCredentialStore::new(); // empty store
        let handler = OutboundHandler::new(SecurityPolicy::default(), store);

        let pfp = make_pfp(RiskLevel::Low, OverrideFlag::Normal);
        let pfp_value = pfp_header_value(&pfp);
        let headers = vec![
            ("x-pfp", pfp_value.as_str()),
            ("x-identity-label", "env:nonexistent/key"),
        ];

        let mut request = OutboundRequest::new();
        let target = InjectionTarget::header("X-API-Key");

        let result = handler
            .handle_outbound(headers, &mut request, &target)
            .await;

        assert!(matches!(result, Err(OutboundError::Credential(_))));
    }

    #[tokio::test]
    async fn test_outbound_query_param_injection() {
        let store = InMemoryCredentialStore::new();
        store.insert("env:test/query", b"query-secret");

        let handler = OutboundHandler::new(SecurityPolicy::default(), store);

        let pfp = make_pfp(RiskLevel::Low, OverrideFlag::Normal);
        let pfp_value = pfp_header_value(&pfp);
        let headers = vec![
            ("x-pfp", pfp_value.as_str()),
            ("x-identity-label", "env:test/query"),
        ];

        let mut request = OutboundRequest::new();
        let target = InjectionTarget::query_param("api_key");

        let result = handler
            .handle_outbound(headers, &mut request, &target)
            .await
            .unwrap();

        assert_eq!(result.decision, OutboundDecision::Allow);
        assert_eq!(request.query_params.get("api_key").unwrap(), "query-secret");
    }

    #[test]
    fn test_outbound_decision_serialization() {
        let decision = OutboundDecision::Reject {
            status: 403,
            reason: "test".to_string(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: OutboundDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, decision);
    }

    #[test]
    fn test_outbound_handler_policy_access() {
        let store = InMemoryCredentialStore::new();
        let policy = SecurityPolicy::default();
        let handler = OutboundHandler::new(policy, store);
        let _ = handler.policy();
    }
}
