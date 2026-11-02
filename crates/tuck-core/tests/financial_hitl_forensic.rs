//! Forensic criteria: prove that the defect is live *right now*.
//!
//! ## Division of labour with the acceptance criteria (stage A', item 3: split the files)
//!
//! | | assertion shape | proves | after the fix |
//! |---|---|---|---|
//! | **this file (forensic)** | `assert_ne!(current, unacceptable)` | the defect **is here** | turns green |
//! | `financial_hitl_acceptance.rs` | `assert_eq!(current, target)` | the target **is not reached** | turns green |
//!
//! Why split: mixed together, a red in stage B cannot be attributed -- "is this red
//! because the defect is still there, or because the target is not reached yet"
//! can only be answered by looking at the assertion shape.
//!
//! ## Discipline (the lesson of stage A', item 1)
//!
//! **This file contains no test that asserts the current behaviour.**
//! It only asserts "it must not be X"; it never asserts "it is X and will stay X" --
//! the latter is a signpost pointing the wrong way. Anything that needs to record
//! current behaviour goes into `CI144-REGISTER.md`, not into an assertion.
//!
//! ## Mutation wording discipline (stage A', item 7)
//!
//! Every `/// Mutation:` line states **which line becomes what**, not
//! "what direction to move in".

use std::time::Duration;

use tuck_core::hitl::{ConfirmStatus, HumanConfirmGate};
use tuck_core::policy::PolicyConfig;
use tuck_core::{
    decide, Decision, OverrideFlag, PfpHeader, ReplayEnable, RiskLevel, SecurityPolicy,
};

/// Mirrors `make_pfp` from `lib.rs:468` (a test fixture; the subject under test is
/// not modified). Bit layout follows the PFP README Byte Layout: byte 2 bits 2-3 =
/// Risk-Level; byte 3 bit 1 = Override-Flag, bit 2 = Replay-Enable.
fn pfp(risk: RiskLevel, of: OverrideFlag, re: ReplayEnable) -> PfpHeader {
    let mut bytes = [0xCF, 0x14, 0, 0];
    bytes[2] = (risk as u8) << 2;
    bytes[3] = (of as u8) << 1 | (re as u8) << 2;
    PfpHeader::from_bytes(bytes).unwrap()
}

// ===========================================================================
// Gap 3 - downgrade => a financial operation walks around HITL
// ===========================================================================

/// **Main criterion - forensic red**
///
/// A financial operation = `CRITICAL(2)` + `Replay-Enable=0` => today it yields `Pass`.
///
/// Why `Pass` is unacceptable: `Decision::NeedHumanConfirm` means "pause and ask a
/// human; on confirmation -> Pass, on timeout -> Reject". Returning `Pass` directly
/// means **the HITL door was never walked through**.
///
/// Mutation: change `ReplayEnable::Disabled => RiskLevel::Medium` in `lib.rs:151` to
///           return `self.risk_level()`; this test turns green.
#[test]
fn financial_operation_with_replay_disabled_must_not_auto_pass() {
    let p = pfp(RiskLevel::Critical, OverrideFlag::Normal, ReplayEnable::Disabled);
    let d = decide(&p, &SecurityPolicy::default());

    assert_ne!(
        d,
        Decision::Pass,
        "CRITICAL (financial / irreversible) + Replay-Enable=0 => currently {d:?}. \
         The downgrade turned an action that needs human confirmation into an outright \
         pass -- HITL was never walked through."
    );
}

/// **Forensic red**: under replay-disabled, `CATASTROPHIC` is **lowered from Reject
/// to Pass**.
///
/// **Turning the replay protection off makes the most dangerous class more permissive.**
///
/// Mutation: change `ReplayEnable::Disabled => RiskLevel::Medium` in `lib.rs:151` to
///           return `self.risk_level()`; this test turns green.
#[test]
fn replay_disabled_must_not_turn_catastrophic_reject_into_pass() {
    let off = pfp(RiskLevel::Catastrophic, OverrideFlag::Normal, ReplayEnable::Disabled);
    assert_ne!(
        decide(&off, &SecurityPolicy::default()),
        Decision::Pass,
        "with replay protection off, CATASTROPHIC went from Reject to Pass -- the \
         compensating measure makes the most dangerous class more permissive, the \
         opposite of PFP Rule 6 item 4, 'prevents high-risk physical attacks via replay'"
    );
}

// ===========================================================================
// Gap 4 - break-glass is on in the default path
// ===========================================================================

/// **Forensic red**: `catastrophic_override` in `SecurityPolicy::default()` is
/// `HardOverridePass`.
///
/// The default path means: not configuring it equals enabling it. Three rulings have
/// already rejected it (ADR-0054 section 5.2 / ROAD-18 B-4 / ADR-0004 D7).
///
/// Mutation: change `catastrophic_override: Decision::HardOverridePass` in `lib.rs:364`
///           to `Decision::Reject`; this test turns green.
#[test]
fn break_glass_must_not_be_enabled_by_default() {
    let pol = SecurityPolicy::default();
    assert_ne!(
        pol.catastrophic_override,
        Decision::HardOverridePass,
        "the default policy opens break-glass as HardOverridePass -- it is on unless \
         configured off, and has been rejected three times (ADR-0054 5.2 / ROAD-18 B-4 \
         / ADR-0004 D7)"
    );
}

/// **Forensic red (stage A', item 4 - new)**: **the second production default**.
///
/// The stage A report only judged `SecurityPolicy::default()` in `lib.rs:364` and
/// **missed `PolicyConfig::default()` in `policy.rs:285`** -- the default used by the
/// TOML configuration path, which is a **second, independent default source**.
///
/// => Fixing only `lib.rs:364` leaves deployments that go through the configuration
/// path with break-glass still on.
///
/// Mutation: change `catastrophic_override: DecisionConfig::HardOverridePass` in
///           `policy.rs:285` to `DecisionConfig::Reject`; this test turns green.
#[test]
fn break_glass_must_not_be_enabled_in_policy_config_default() {
    let pol = PolicyConfig::default().to_policy();
    assert_ne!(
        pol.catastrophic_override,
        Decision::HardOverridePass,
        "PolicyConfig::default() (policy.rs:285) is the SECOND production default and \
         it also opens break-glass. The TOML configuration path and \
         SecurityPolicy::default() are two independent default sources, so fixing one \
         of them is the same as fixing neither"
    );
}

/// **Forensic red (stage A', item 4 - new)**: **a test fixture hard-codes break-glass**.
///
/// `hot_reload.rs:327` (`default_policy_toml`) and `:343` (`strict_policy_toml`) both
/// write `catastrophic_override = "hard_override_pass"` into fixtures.
///
/// **Classification (correcting the stage A report)**: both live inside
/// `#[cfg(test)] mod tests` (starting at `hot_reload.rs:302`) -- they are **not**
/// production defaults, they are fixtures. => Counting them as "places where the
/// default is on" was **my miscount** (see the correction in `CI144-REGISTER.md`).
///
/// They still have to be judged: if the production default is changed without changing
/// them, the hot-reload tests keep asserting a **value that has been forbidden**, and
/// become a leftover signpost.
///
/// Mutation: delete or change the two `hard_override_pass` literals in `hot_reload.rs`;
///           this test turns green.
#[test]
fn no_test_fixture_may_encode_break_glass() {
    let src = include_str!("../src/hot_reload.rs");
    let hits: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("hard_override_pass"))
        .map(|(i, l)| (i + 1, l))
        .collect();

    assert!(
        hits.is_empty(),
        "hot_reload.rs fixtures still contain a break-glass literal (they must be \
         changed together with the production default):\n{}",
        hits.iter()
            .map(|(n, l)| format!("  line {n}: {}", l.trim()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ===========================================================================
// Gap - an unanswered request is expressed as a timeout
// ===========================================================================

/// **Forensic red - an unanswered request must not be expressed as a timeout**
///
/// Build a gate, call `request()`, then **neither confirm nor reject** (= nobody
/// answered). After the timeout, `history()` records `TimedOut`.
///
/// Why that is a defect: `ConfirmStatus::TimedOut` means "there is someone, but they
/// did not answer in time"; this scenario is "**there is no responder at all**".
/// => Two facts are folded into one value => it no longer has the shape of anaphase's
/// closed four-value `ApprovalOutcome` (`AllowedOnce/Rejected/Cancelled/Unavailable`).
///
/// WARNING **named limit of this test** (a prerequisite for stage B, see the
/// responder-registration section of `CI144-REGISTER.md`): adding an enum variant
/// **does not fix this** -- whether the `rx` returned by `request()` is dropped is
/// something the gate cannot observe, so it cannot tell "someone holds the rx and did
/// not answer" from "nobody holds the rx".
/// => Stage B needs a **responder-registration design first**, otherwise this becomes a
/// permanently green fake implementation ("someone holds the rx, so someone is there").
///
/// Mutation: add an `Unavailable` variant to `ConfirmStatus` and make `request()` record
///           it (instead of `TimedOut`) when **no responder is registered**; this test
///           turns green.
#[tokio::test]
async fn unanswered_must_not_be_recorded_as_timed_out() {
    let gate = HumanConfirmGate::new(Duration::from_millis(100));
    let (_id, _rx) = gate
        .request("Critical", "Executive", "wire 100k to beneficiary")
        .await;

    // Nobody answers: no confirm, no reject. Let the timeout task run out.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let history = gate.history().await;
    assert_eq!(history.len(), 1, "there must be exactly one entry: the unanswered request");
    assert_ne!(
        history[0].status,
        ConfirmStatus::TimedOut,
        "'nobody answered' and 'someone did not answer in time' are two facts; both are \
         recorded as TimedOut today. In production Tuck, confirm() is unreachable, so \
         nobody answering is the normal case, yet it is expressed as a timeout -- that \
         is pretending somebody is listening"
    );
}

// ===========================================================================
// Counter-samples (**must stay green**) - guard against over-fixing / collateral damage
// ===========================================================================

/// Counter-sample 1: `CRITICAL` + `RE=1` => `NeedHumanConfirm` (must hold before and
/// after the fix).
#[test]
fn critical_with_replay_enabled_still_needs_human_confirm() {
    let p = pfp(RiskLevel::Critical, OverrideFlag::Normal, ReplayEnable::Enabled);
    assert_eq!(
        decide(&p, &SecurityPolicy::default()),
        Decision::NeedHumanConfirm,
        "CRITICAL + RE=1 => NeedHumanConfirm (baseline; must hold before and after the fix)"
    );
}

/// Counter-sample 2: low risk is not caught in the blast radius.
#[test]
fn low_and_medium_risk_stay_pass() {
    let low = pfp(RiskLevel::Low, OverrideFlag::Normal, ReplayEnable::Enabled);
    assert_eq!(decide(&low, &SecurityPolicy::default()), Decision::Pass);

    let med = pfp(RiskLevel::Medium, OverrideFlag::Normal, ReplayEnable::Enabled);
    assert_eq!(decide(&med, &SecurityPolicy::default()), Decision::Pass);
}

/// Counter-sample 3: a **genuine** MEDIUM (not produced by a downgrade) stays `Pass`.
/// The only difference from criterion 1 is whether a downgrade happened => this makes
/// sure the fix targets **the act of downgrading**, not `medium` as a value.
#[test]
fn genuine_medium_is_unaffected_by_the_downgrade_fix() {
    let m = pfp(RiskLevel::Medium, OverrideFlag::Normal, ReplayEnable::Disabled);
    assert_eq!(
        decide(&m, &SecurityPolicy::default()),
        Decision::Pass,
        "genuine MEDIUM + RE=0 is still MEDIUM => Pass. The fix targets the DOWNGRADE itself"
    );
}

/// Counter-sample 4: **CATASTROPHIC + HO + RE=1** lands on `policy.catastrophic_override`.
/// This test **does not** assert whether that value is right (that is the scope of
/// gap 4's ruling); it only pins "with RE=1 the HO path really is reached", as a
/// comparison baseline for the acceptance criteria.
#[test]
fn hard_override_path_is_reachable_when_replay_enabled() {
    let p = pfp(RiskLevel::Catastrophic, OverrideFlag::HardOverride, ReplayEnable::Enabled);
    let d = decide(&p, &SecurityPolicy::default());
    assert_eq!(
        d,
        SecurityPolicy::default().catastrophic_override,
        "with RE=1, HO + CATASTROPHIC must land on policy.catastrophic_override (baseline)"
    );
}

// ===========================================================================
// Guard - single source of truth (SSOT): currently GREEN, it guards the future
// ===========================================================================

/// Guard: the runtime default is a **projection** of the config default, and both must
/// still equal the golden policy written out literally here.
///
/// Why the literal: after A3 the old drift check compared X with X (the projection makes
/// the two sides the same expression), so it was permanently green -- a detector that died
/// inside the very change it existed to protect. A golden literal keeps the ability to go
/// red: it is independent of both implementations.
///
/// Mutation: change any default field in `PolicyConfig::default()` (or drop the projection
/// and change `SecurityPolicy::default()` alone) => this test turns red and names the field.
#[test]
fn the_defaults_are_a_projection_and_match_the_golden_policy() {
    let runtime = SecurityPolicy::default();
    let config = PolicyConfig::default().to_policy();

    // Golden policy, written out. This is the value the two implementations must produce.
    let golden = [
        ("low", Decision::Pass),
        ("medium", Decision::Pass),
        ("critical", Decision::NeedHumanConfirm),
        ("catastrophic", Decision::Reject),
        // A2 (2026-11-01) moves this to Reject; until then the golden records the fact.
        ("catastrophic_override", Decision::HardOverridePass),
    ];
    let actual = [
        ("low", runtime.low),
        ("medium", runtime.medium),
        ("critical", runtime.critical),
        ("catastrophic", runtime.catastrophic),
        ("catastrophic_override", runtime.catastrophic_override),
    ];
    for ((name, want), (name2, got)) in golden.iter().zip(actual.iter()) {
        assert_eq!(name, name2);
        assert_eq!(
            format!("{want:?}"),
            format!("{got:?}"),
            "the default drifted from the golden policy on {name}"
        );
    }
    assert_eq!(
        format!("{:?}", runtime),
        format!("{:?}", config),
        "the runtime default must remain a projection of the config default"
    );
    assert_eq!(
        runtime.external_additional_check,
        true,
        "external_additional_check must stay on by default"
    );
}
