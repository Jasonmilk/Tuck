//! CATASTROPHIC hard override — non-negotiable emergency pass with human notification.
//!
//! When `decide()` returns `Decision::HardOverridePass` (CATASTROPHIC risk +
//! Override-Flag), the catastrophic gate triggers an emergency signal and
//! notifies humans in parallel. This is the *non-negotiable* part of the
//! CI-144 protocol — any compliant implementation must handle this.
//!
//! # Design Principle
//!
//! **按需驱动 (event-driven)**: CATASTROPHIC events are event-driven, not
//! polling. A `tokio::sync::Notify` or broadcast channel fires only when a
//! CATASTROPHIC event occurs — no busy-waiting, no periodic checks.
//!
//! **白盒可审计**: Every CATASTROPHIC event is recorded with full context
//! (PFP fields, timestamp, source) for post-incident audit.
//!
//! **优先级**: CATASTROPHIC events use a dedicated high-priority channel,
//! separate from regular decision traffic. They cannot be blocked by regular
//! load.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex, Notify};
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// Unique identifier for a catastrophic event.
pub type CatastrophicEventId = Uuid;

/// CATASTROPHIC event — recorded when HardOverridePass is triggered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatastrophicEvent {
    /// Unique event ID.
    pub id: CatastrophicEventId,
    /// PFP risk level (should be CATASTROPHIC).
    pub risk_level: String,
    /// PFP modality.
    pub modality: String,
    /// PFP override flag (should be HARD_OVERRIDE).
    pub override_flag: String,
    /// Frame/source description.
    pub description: String,
    /// Creation timestamp (unix seconds).
    pub created_at: u64,
    /// Whether humans have been notified.
    pub humans_notified: bool,
    /// Event status.
    pub status: CatastrophicStatus,
}

/// Status of a catastrophic event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatastrophicStatus {
    /// Event triggered,正在处理.
    Triggered,
    /// Event acknowledged by human.
    Acknowledged,
    /// Event resolved.
    Resolved,
}

// ============================================================================
// Catastrophic Gate
// ============================================================================

/// CATASTROPHIC hard override gate.
///
/// Manages catastrophic events:
/// - Triggering an emergency signal (`Notify`)
/// - Broadcasting to human subscribers (`broadcast::Sender`)
/// - Recording events for audit
/// - High-priority channel (separate from regular traffic)
///
/// # Usage
///
/// ```rust,ignore
/// use tuck_core::catastrophic::CatastrophicGate;
/// use std::time::Duration;
///
/// let gate = CatastrophicGate::new(100); // max 100 subscribers
///
/// // Subscribe for human notifications
/// let mut rx = gate.subscribe();
/// tokio::spawn(async move {
///     while let Ok(event) = rx.recv().await {
///         println!("CATASTROPHIC: {:?}", event);
///         // Send alert to human (Cellrix/CLI/email/SMS)
///     }
/// });
///
/// // When decide() returns HardOverridePass:
/// gate.trigger("CATASTROPHIC", "EXECUTIVE", "HARD_OVERRIDE", "Emergency shutdown").await;
/// ```
#[derive(Debug, Clone)]
pub struct CatastrophicGate {
    inner: Arc<Mutex<GateInner>>,
    /// Emergency signal — fires on every CATASTROPHIC event.
    emergency: Arc<Notify>,
    /// Broadcast channel for human subscribers.
    broadcast: broadcast::Sender<CatastrophicEvent>,
}

#[derive(Debug)]
struct GateInner {
    /// Event history (for audit).
    history: Vec<CatastrophicEvent>,
    /// Active events (not yet resolved).
    active: Vec<CatastrophicEventId>,
}

impl CatastrophicGate {
    /// Create a new catastrophic gate.
    ///
    /// `max_subscribers` is the capacity of the broadcast channel.
    /// Events are buffered up to this capacity; if subscribers are slow,
    /// older events may be dropped (lagging subscribers receive RecvError).
    pub fn new(max_subscribers: usize) -> Self {
        let (tx, _rx) = broadcast::channel(max_subscribers);
        Self {
            inner: Arc::new(Mutex::new(GateInner {
                history: Vec::new(),
                active: Vec::new(),
            })),
            emergency: Arc::new(Notify::new()),
            broadcast: tx,
        }
    }

    /// Trigger a CATASTROPHIC event.
    ///
    /// This:
    /// 1. Creates a `CatastrophicEvent` with full context
    /// 2. Records it in history (for audit)
    /// 3. Fires the emergency signal (`Notify`)
    /// 4. Broadcasts to all human subscribers
    ///
    /// This is non-blocking — it returns immediately after triggering.
    /// Human notification happens asynchronously via subscribers.
    pub async fn trigger(
        &self,
        risk_level: &str,
        modality: &str,
        override_flag: &str,
        description: &str,
    ) -> CatastrophicEventId {
        let event = CatastrophicEvent {
            id: Uuid::new_v4(),
            risk_level: risk_level.to_string(),
            modality: modality.to_string(),
            override_flag: override_flag.to_string(),
            description: description.to_string(),
            created_at: unix_now(),
            humans_notified: false,
            status: CatastrophicStatus::Triggered,
        };

        let event_id = event.id;

        // Record in history and active list
        {
            let mut inner = self.inner.lock().await;
            inner.history.push(event.clone());
            inner.active.push(event_id);
        }

        // Fire emergency signal (high-priority, non-blocking)
        self.emergency.notify_waiters();

        // Broadcast to human subscribers (non-blocking)
        // If no subscribers or channel full, the event is still recorded in history
        let _ = self.broadcast.send(event);

        event_id
    }

    /// Subscribe to CATASTROPHIC events (for human notification).
    ///
    /// Returns a broadcast receiver that receives every triggered event.
    /// Subscribers should handle events asynchronously (e.g., send alert to
    /// Cellrix/CLI/email/SMS).
    pub fn subscribe(&self) -> broadcast::Receiver<CatastrophicEvent> {
        self.broadcast.subscribe()
    }

    /// Wait for the next CATASTROPHIC emergency signal.
    ///
    /// This is a high-priority wait — it returns immediately when an event
    /// is triggered, without polling. Use this for critical response paths
    /// that need to react instantly.
    pub async fn wait_emergency(&self) {
        self.emergency.notified().await;
    }

    /// Acknowledge a catastrophic event (human has seen it).
    pub async fn acknowledge(&self, id: &CatastrophicEventId) -> bool {
        self.set_status(id, CatastrophicStatus::Acknowledged).await
    }

    /// Resolve a catastrophic event (incident handled).
    pub async fn resolve(&self, id: &CatastrophicEventId) -> bool {
        let mut inner = self.inner.lock().await;
        if let Some(event) = inner.history.iter_mut().find(|e| e.id == *id) {
            event.status = CatastrophicStatus::Resolved;
            inner.active.retain(|&eid| eid != *id);
            true
        } else {
            false
        }
    }

    /// Set the status of a catastrophic event.
    async fn set_status(&self, id: &CatastrophicEventId, status: CatastrophicStatus) -> bool {
        let mut inner = self.inner.lock().await;
        if let Some(event) = inner.history.iter_mut().find(|e| e.id == *id) {
            event.status = status;
            true
        } else {
            false
        }
    }

    /// Get a catastrophic event by ID.
    pub async fn get_event(&self, id: &CatastrophicEventId) -> Option<CatastrophicEvent> {
        let inner = self.inner.lock().await;
        inner.history.iter().find(|e| e.id == *id).cloned()
    }

    /// Get all active (unresolved) catastrophic events.
    pub async fn active_events(&self) -> Vec<CatastrophicEvent> {
        let inner = self.inner.lock().await;
        inner
            .history
            .iter()
            .filter(|e| e.status != CatastrophicStatus::Resolved)
            .cloned()
            .collect()
    }

    /// Get event history (for audit).
    pub async fn history(&self) -> Vec<CatastrophicEvent> {
        let inner = self.inner.lock().await;
        inner.history.clone()
    }

    /// Get the number of active catastrophic events.
    pub async fn active_count(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.active.len()
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
    use std::time::Duration;

    #[tokio::test]
    async fn test_trigger_creates_event() {
        let gate = CatastrophicGate::new(10);
        let id = gate
            .trigger("CATASTROPHIC", "EXECUTIVE", "HARD_OVERRIDE", "Emergency")
            .await;

        assert_eq!(gate.active_count().await, 1);
        let event = gate.get_event(&id).await.unwrap();
        assert_eq!(event.risk_level, "CATASTROPHIC");
        assert_eq!(event.modality, "EXECUTIVE");
        assert_eq!(event.override_flag, "HARD_OVERRIDE");
        assert_eq!(event.status, CatastrophicStatus::Triggered);
    }

    #[tokio::test]
    async fn test_subscriber_receives_event() {
        let gate = CatastrophicGate::new(10);
        let mut rx = gate.subscribe();

        let id = gate
            .trigger("CATASTROPHIC", "EXECUTIVE", "HARD_OVERRIDE", "Test event")
            .await;

        let received = rx.recv().await.unwrap();
        assert_eq!(received.id, id);
        assert_eq!(received.description, "Test event");
    }

    #[tokio::test]
    async fn test_emergency_signal() {
        let gate = CatastrophicGate::new(10);
        let gate_clone = gate.clone();

        // Spawn a task that waits for emergency
        let handle = tokio::spawn(async move {
            gate_clone.wait_emergency().await;
            true
        });

        // Small delay to ensure the wait task is ready
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Trigger event
        gate.trigger("CATASTROPHIC", "EXECUTIVE", "HARD_OVERRIDE", "Emergency").await;

        // Wait for the signal task to complete
        let result = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_acknowledge_and_resolve() {
        let gate = CatastrophicGate::new(10);
        let id = gate
            .trigger("CATASTROPHIC", "EXECUTIVE", "HARD_OVERRIDE", "Test")
            .await;

        assert!(gate.acknowledge(&id).await);
        let event = gate.get_event(&id).await.unwrap();
        assert_eq!(event.status, CatastrophicStatus::Acknowledged);
        assert_eq!(gate.active_count().await, 1); // still active

        assert!(gate.resolve(&id).await);
        let event = gate.get_event(&id).await.unwrap();
        assert_eq!(event.status, CatastrophicStatus::Resolved);
        assert_eq!(gate.active_count().await, 0); // resolved, no longer active
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let gate = CatastrophicGate::new(10);
        let mut rx1 = gate.subscribe();
        let mut rx2 = gate.subscribe();

        gate.trigger("CATASTROPHIC", "EXECUTIVE", "HARD_OVERRIDE", "Broadcast test").await;

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert_eq!(e1.id, e2.id);
        assert_eq!(e1.description, "Broadcast test");
    }

    #[tokio::test]
    async fn test_history_records_all_events() {
        let gate = CatastrophicGate::new(10);
        gate.trigger("CATASTROPHIC", "EXECUTIVE", "HARD_OVERRIDE", "Event 1").await;
        gate.trigger("CATASTROPHIC", "SENSOR_FEED", "HARD_OVERRIDE", "Event 2").await;

        let history = gate.history().await;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].description, "Event 1");
        assert_eq!(history[1].description, "Event 2");
    }

    #[tokio::test]
    async fn test_active_events_excludes_resolved() {
        let gate = CatastrophicGate::new(10);
        let id1 = gate.trigger("CATASTROPHIC", "EXECUTIVE", "HARD_OVERRIDE", "Event 1").await;
        gate.trigger("CATASTROPHIC", "SENSOR_FEED", "HARD_OVERRIDE", "Event 2").await;

        assert_eq!(gate.active_events().await.len(), 2);

        gate.resolve(&id1).await;
        assert_eq!(gate.active_events().await.len(), 1);
        assert_eq!(gate.active_events().await[0].description, "Event 2");
    }

    #[tokio::test]
    async fn test_event_serialization() {
        let event = CatastrophicEvent {
            id: Uuid::nil(),
            risk_level: "CATASTROPHIC".to_string(),
            modality: "EXECUTIVE".to_string(),
            override_flag: "HARD_OVERRIDE".to_string(),
            description: "Test".to_string(),
            created_at: 1234567890,
            humans_notified: false,
            status: CatastrophicStatus::Triggered,
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: CatastrophicEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.risk_level, event.risk_level);
        assert_eq!(parsed.status, event.status);
    }

    #[tokio::test]
    async fn test_trigger_non_blocking() {
        let gate = CatastrophicGate::new(10);
        // Trigger should return immediately, even with no subscribers
        let start = std::time::Instant::now();
        gate.trigger("CATASTROPHIC", "EXECUTIVE", "HARD_OVERRIDE", "Non-blocking test").await;
        assert!(start.elapsed() < Duration::from_millis(100));
    }
}
