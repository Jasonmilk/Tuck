//! HITL (Human-In-The-Loop) execution gate — human confirmation for high-risk decisions.
//!
//! When `decide()` returns `Decision::NeedHumanConfirm`, the HITL gate pauses
//! the frame and requests human confirmation. If confirmed, the frame passes;
//! if rejected or timed out, the frame is rejected.
//!
//! # Design Principle
//!
//! **按需驱动 (event-driven)**: The HITL gate is event-driven, not polling.
//! A confirmation request is created only when `NeedHumanConfirm` is returned.
//! The gate waits asynchronously for human input or timeout — no busy-waiting.
//!
//! **极致解耦**: HITL is separate from the hard real-time `decide()` path.
//! `decide()` returns immediately with `NeedHumanConfirm`; HITL handles the
//! asynchronous confirmation flow in a separate task.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;

use crate::Decision;

// ============================================================================
// Types
// ============================================================================

/// Unique identifier for a human confirmation request.
pub type ConfirmRequestId = Uuid;

/// Human confirmation request — created when `decide()` returns `NeedHumanConfirm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmRequest {
    /// Unique request ID.
    pub id: ConfirmRequestId,
    /// PFP risk level (for display to human).
    pub risk_level: String,
    /// PFP modality (for display to human).
    pub modality: String,
    /// Frame description (for display to human).
    pub description: String,
    /// Creation timestamp (unix seconds).
    pub created_at: u64,
    /// Timeout in seconds.
    pub timeout_secs: u64,
    /// Current status.
    pub status: ConfirmStatus,
}

/// Status of a confirmation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmStatus {
    /// Waiting for human confirmation.
    Pending,
    /// Confirmed by human — frame should pass.
    Confirmed,
    /// Rejected by human — frame should be rejected.
    Rejected,
    /// Timed out — frame should be rejected (fail-closed).
    TimedOut,
}

/// Result of a confirmation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmResult {
    /// Human confirmed — pass the frame.
    Pass,
    /// Human rejected or timed out — reject the frame (fail-closed).
    Reject,
}

impl From<ConfirmResult> for Decision {
    fn from(value: ConfirmResult) -> Self {
        match value {
            ConfirmResult::Pass => Decision::Pass,
            ConfirmResult::Reject => Decision::Reject,
        }
    }
}

// ============================================================================
// HITL Gate
// ============================================================================

/// HITL (Human-In-The-Loop) execution gate.
///
/// Manages pending confirmation requests. Supports:
/// - Creating a confirmation request (returns a oneshot receiver for the result)
/// - Confirming/rejecting a request by ID
/// - Automatic timeout (fail-closed: timeout → Reject)
/// - Listing pending requests (for UI/Cellrix display)
///
/// # Usage
///
/// ```rust,ignore
/// use tuck_core::hitl::HumanConfirmGate;
/// use std::time::Duration;
///
/// let gate = HumanConfirmGate::new(Duration::from_secs(30));
///
/// // When decide() returns NeedHumanConfirm:
/// let (id, rx) = gate.request("CRITICAL", "EXECUTIVE", "Delete production database").await;
///
/// // Human confirms (via UI/API):
/// gate.confirm(&id).await;
///
/// // Wait for result (or timeout):
/// let result = rx.await.unwrap(); // Pass or Reject
/// ```
#[derive(Clone)]
pub struct HumanConfirmGate {
    inner: Arc<Mutex<GateInner>>,
    default_timeout: Duration,
}

struct GateInner {
    /// Pending requests: request_id → (request, oneshot sender).
    pending: HashMap<ConfirmRequestId, (ConfirmRequest, oneshot::Sender<ConfirmResult>)>,
    /// Request history (for audit).
    history: Vec<ConfirmRequest>,
}

impl HumanConfirmGate {
    /// Create a new HITL gate with the given default timeout.
    pub fn new(default_timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(GateInner {
                pending: HashMap::new(),
                history: Vec::new(),
            })),
            default_timeout,
        }
    }

    /// Create a confirmation request.
    ///
    /// Returns the request ID and a oneshot receiver that resolves when the
    /// request is confirmed, rejected, or timed out.
    ///
    /// Spawns a timeout task that automatically rejects the request if no
    /// human action is taken within the timeout (fail-closed).
    pub async fn request(
        &self,
        risk_level: &str,
        modality: &str,
        description: &str,
    ) -> (ConfirmRequestId, oneshot::Receiver<ConfirmResult>) {
        self.request_with_timeout(risk_level, modality, description, self.default_timeout)
            .await
    }

    /// Create a confirmation request with a custom timeout.
    pub async fn request_with_timeout(
        &self,
        risk_level: &str,
        modality: &str,
        description: &str,
        timeout: Duration,
    ) -> (ConfirmRequestId, oneshot::Receiver<ConfirmResult>) {
        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();

        let request = ConfirmRequest {
            id,
            risk_level: risk_level.to_string(),
            modality: modality.to_string(),
            description: description.to_string(),
            created_at: unix_now(),
            timeout_secs: timeout.as_secs(),
            status: ConfirmStatus::Pending,
        };

        {
            let mut inner = self.inner.lock().await;
            inner.pending.insert(id, (request.clone(), tx));
        }

        // Spawn timeout task (fail-closed: timeout → Reject)
        let gate_clone = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            // If still pending, timeout → reject
            let _ = gate_clone.timeout_if_pending(&id).await;
        });

        (id, rx)
    }

    /// Confirm a request by ID (human approved).
    ///
    /// Returns `true` if the request was pending and is now confirmed.
    pub async fn confirm(&self, id: &ConfirmRequestId) -> bool {
        self.resolve(id, ConfirmStatus::Confirmed, ConfirmResult::Pass).await
    }

    /// Reject a request by ID (human denied).
    ///
    /// Returns `true` if the request was pending and is now rejected.
    pub async fn reject(&self, id: &ConfirmRequestId) -> bool {
        self.resolve(id, ConfirmStatus::Rejected, ConfirmResult::Reject).await
    }

    /// Time out a request if still pending (fail-closed).
    ///
    /// Returns `true` if the request was pending and is now timed out.
    async fn timeout_if_pending(&self, id: &ConfirmRequestId) -> bool {
        self.resolve(id, ConfirmStatus::TimedOut, ConfirmResult::Reject).await
    }

    /// Resolve a request with the given status and result.
    async fn resolve(
        &self,
        id: &ConfirmRequestId,
        status: ConfirmStatus,
        result: ConfirmResult,
    ) -> bool {
        let mut inner = self.inner.lock().await;
        if let Some((mut request, tx)) = inner.pending.remove(id) {
            request.status = status;
            inner.history.push(request);
            // Send result (ignore error if receiver was dropped)
            let _ = tx.send(result);
            true
        } else {
            false
        }
    }

    /// Get a pending request by ID.
    pub async fn get_pending(&self, id: &ConfirmRequestId) -> Option<ConfirmRequest> {
        let inner = self.inner.lock().await;
        inner.pending.get(id).map(|(r, _)| r.clone())
    }

    /// List all pending requests (for UI/Cellrix display).
    pub async fn list_pending(&self) -> Vec<ConfirmRequest> {
        let inner = self.inner.lock().await;
        inner.pending.values().map(|(r, _)| r.clone()).collect()
    }

    /// Get the number of pending requests.
    pub async fn pending_count(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.pending.len()
    }

    /// Get request history (for audit).
    pub async fn history(&self) -> Vec<ConfirmRequest> {
        let inner = self.inner.lock().await;
        inner.history.clone()
    }
}

// ============================================================================
// Helper
// ============================================================================

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_request_creation() {
        let gate = HumanConfirmGate::new(Duration::from_secs(30));
        let (id, _rx) = gate.request("CRITICAL", "EXECUTIVE", "Test action").await;
        assert_eq!(gate.pending_count().await, 1);
        let req = gate.get_pending(&id).await.unwrap();
        assert_eq!(req.status, ConfirmStatus::Pending);
        assert_eq!(req.risk_level, "CRITICAL");
        assert_eq!(req.modality, "EXECUTIVE");
    }

    #[tokio::test]
    async fn test_confirm() {
        let gate = HumanConfirmGate::new(Duration::from_secs(30));
        let (id, rx) = gate.request("CRITICAL", "EXECUTIVE", "Test action").await;

        assert!(gate.confirm(&id).await);
        assert_eq!(gate.pending_count().await, 0);

        let result = rx.await.unwrap();
        assert_eq!(result, ConfirmResult::Pass);
        assert_eq!(Decision::from(result), Decision::Pass);
    }

    #[tokio::test]
    async fn test_reject() {
        let gate = HumanConfirmGate::new(Duration::from_secs(30));
        let (id, rx) = gate.request("CRITICAL", "EXECUTIVE", "Test action").await;

        assert!(gate.reject(&id).await);
        let result = rx.await.unwrap();
        assert_eq!(result, ConfirmResult::Reject);
        assert_eq!(Decision::from(result), Decision::Reject);
    }

    #[tokio::test]
    async fn test_timeout_fail_closed() {
        let gate = HumanConfirmGate::new(Duration::from_millis(100));
        let (_id, rx) = gate.request("CRITICAL", "EXECUTIVE", "Test action").await;

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(200)).await;

        let result = rx.await.unwrap();
        assert_eq!(result, ConfirmResult::Reject); // fail-closed
        assert_eq!(gate.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_confirm_already_resolved() {
        let gate = HumanConfirmGate::new(Duration::from_secs(30));
        let (id, _rx) = gate.request("CRITICAL", "EXECUTIVE", "Test action").await;

        assert!(gate.confirm(&id).await);
        // Second confirm should fail (already resolved)
        assert!(!gate.confirm(&id).await);
    }

    #[tokio::test]
    async fn test_list_pending() {
        let gate = HumanConfirmGate::new(Duration::from_secs(30));
        let (_id1, _rx1) = gate.request("CRITICAL", "EXECUTIVE", "Action 1").await;
        let (_id2, _rx2) = gate.request("MEDIUM", "RENDER", "Action 2").await;

        let pending = gate.list_pending().await;
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn test_history() {
        let gate = HumanConfirmGate::new(Duration::from_secs(30));
        let (id1, _rx1) = gate.request("CRITICAL", "EXECUTIVE", "Action 1").await;
        let (id2, _rx2) = gate.request("MEDIUM", "RENDER", "Action 2").await;

        gate.confirm(&id1).await;
        gate.reject(&id2).await;

        let history = gate.history().await;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].status, ConfirmStatus::Confirmed);
        assert_eq!(history[1].status, ConfirmStatus::Rejected);
    }

    #[tokio::test]
    async fn test_custom_timeout() {
        let gate = HumanConfirmGate::new(Duration::from_secs(30));
        let (_id, rx) = gate
            .request_with_timeout("CRITICAL", "EXECUTIVE", "Test", Duration::from_millis(50))
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let result = rx.await.unwrap();
        assert_eq!(result, ConfirmResult::Reject); // fail-closed
    }

    #[tokio::test]
    async fn test_confirm_status_serialization() {
        for status in [
            ConfirmStatus::Pending,
            ConfirmStatus::Confirmed,
            ConfirmStatus::Rejected,
            ConfirmStatus::TimedOut,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: ConfirmStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, parsed);
        }
    }
}
