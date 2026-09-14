//! Notification sinks for admission verdicts (H-5).
//!
//! **The gateway ships no implementation** (`ADR-0005` D8). Which channel a
//! denial travels on — webhook, queue, pager, log shipper — is the
//! deployment's decision, not the gateway's preset. This module defines the
//! seam and nothing else; with no sink registered, nothing is sent.

/// What a sink is told when admission denies a call.
///
/// Carries exactly what the audit record carries — one fact, one shape — so a
/// sink never has to re-derive who wanted to go where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// Correlates with the audit chain and the caller's own ledgers.
    pub trace_id: String,
    /// Scope of the caller. `None` when the caller carried no scope, which is
    /// itself a denial reason worth surfacing.
    pub scope: Option<String>,
    pub supplier: Option<String>,
    pub model: Option<String>,
    /// Rule that denied the call. `None` ⇒ fell through to the default action.
    pub rule_id: Option<String>,
    /// True when the denial was recorded but not enforced (observe mode).
    pub observe_only: bool,
}

/// Receives admission denials. Implementations are injected by the deployment.
///
/// Called on the request path, so implementations must not block: hand the
/// event off and return.
pub trait Notify: Send + Sync {
    fn on_denial(&self, denial: &Denial);
}

/// Fan out one denial to every registered sink.
///
/// A sink that panics or is slow is a deployment problem, but it must not
/// take the gateway down with it — hence the catch, and hence "hand off and
/// return" in the trait contract.
pub fn fanout(sinks: &[std::sync::Arc<dyn Notify>], denial: &Denial) {
    for sink in sinks {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sink.on_denial(denial)
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Recorder(Arc<Mutex<Vec<Denial>>>);

    impl Notify for Recorder {
        fn on_denial(&self, d: &Denial) {
            self.0.lock().expect("recorder lock").push(d.clone());
        }
    }

    fn denial() -> Denial {
        Denial {
            trace_id: "t1".into(),
            scope: Some("s".into()),
            supplier: Some("agnes".into()),
            model: Some("m1".into()),
            rule_id: None,
            observe_only: false,
        }
    }

    #[test]
    fn no_sinks_means_nothing_is_sent() {
        // The default: no channel is built in.
        fanout(&[], &denial());
    }

    #[test]
    fn every_sink_receives_the_denial() {
        let a = Arc::new(Mutex::new(Vec::new()));
        let b = Arc::new(Mutex::new(Vec::new()));
        let sinks: Vec<Arc<dyn Notify>> = vec![
            Arc::new(Recorder(a.clone())),
            Arc::new(Recorder(b.clone())),
        ];
        fanout(&sinks, &denial());
        assert_eq!(a.lock().unwrap().len(), 1);
        assert_eq!(b.lock().unwrap().len(), 1);
        assert_eq!(a.lock().unwrap()[0], denial());
    }

    #[test]
    fn a_panicking_sink_does_not_stop_the_others() {
        struct Panic;
        impl Notify for Panic {
            fn on_denial(&self, _: &Denial) {
                panic!("sink is broken");
            }
        }

        let ok = Arc::new(Mutex::new(Vec::new()));
        let sinks: Vec<Arc<dyn Notify>> = vec![Arc::new(Panic), Arc::new(Recorder(ok.clone()))];
        fanout(&sinks, &denial());
        assert_eq!(ok.lock().unwrap().len(), 1, "the healthy sink still ran");
    }
}
