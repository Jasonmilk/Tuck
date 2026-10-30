//! Acceptance criteria -- prove that "the target state is not reached yet".
//!
//! ## Division of labour with the forensic criteria (stage A', item 3: split the files)
//!
//! | | assertion shape | proves |
//! |---|---|---|
//! | `financial_hitl_forensic.rs` | `assert_ne!(current, unacceptable)` | the defect **is here** |
//! | **this file** | `assert_eq!(current, target)` | the target **is not reached** |
//!
//! This file asserts **how things should look once the rulings land**. The tests are red
//! now because the target is not reached; after the stage B fix they should turn green --
//! and on that day they stop being "acceptance criteria" and become "the regression net".
//!
//! WARNING: **this file is the only place in the crate allowed to assert a target value.**
//! If a ruling is overturned, change this file first, then the forensic criteria.
//!
//! ## Discipline
//! Every `/// Mutation:` line states **which line becomes what**, not "what direction to
//! move in".

use tuck_core::{
    decide, Decision, OverrideFlag, PfpHeader, ReplayEnable, RiskLevel, SecurityPolicy,
};

fn pfp(risk: RiskLevel, of: OverrideFlag, re: ReplayEnable) -> PfpHeader {
    let mut bytes = [0xCF, 0x14, 0, 0];
    bytes[2] = (risk as u8) << 2;
    bytes[3] = (of as u8) << 1 | (re as u8) << 2;
    PfpHeader::from_bytes(bytes).unwrap()
}

// ===========================================================================
// ROAD-48 section 2, positive sample -- **previously covered by zero criteria**
// ===========================================================================

/// **ROAD-48 section 2 - acceptance red**
///
/// `HARD_OVERRIDE` + `CATASTROPHIC` + `Replay-Enable=0` => should be **`Reject`**.
/// Today it is actually **`Pass`**, and **no criterion has ever covered this path**
/// (the assertion at `lib.rs:513` asserts `Pass`, not `Reject`).
///
/// ### Why this is worse than "a downgrade" (**a net loss on two axes**)
///
/// Definition of `Decision::HardOverridePass` (`lib.rs:331-333`):
/// "unconditional pass with highest priority, **emergency signal to human in parallel**".
/// => It at least **raises an emergency signal to a human in parallel**.
///
/// Rule 6's downgrade turns it into `Pass` (`lib.rs:325`: the frame continues to flow, no
/// signal).
/// => **Net effect: from "highest-priority pass + parallel alert" down to "silent pass" --
///    Rule 6 item 4 really does "prevent hard override", but the price is losing the
///    alert with it.**
///
/// => Hence this line: "fixing it is not a deviation from the spec, it restores the half
/// that was already in the spec's stated intent (the alert)".
///
/// Mutation: change `ReplayEnable::Disabled => RiskLevel::Medium` in `lib.rs:151` to
///           return `self.risk_level()`; this test turns green.
#[test]
fn road48_hard_override_catastrophic_replay_disabled_must_reject() {
    let p = pfp(RiskLevel::Catastrophic, OverrideFlag::HardOverride, ReplayEnable::Disabled);
    let d = decide(&p, &SecurityPolicy::default());

    assert_eq!(
        d,
        Decision::Reject,
        "ROAD-48 section 2: HO + CATASTROPHIC + RE=0 => Reject. Currently {d:?} -- the \
         downgrade turned 'pass + parallel alert' into 'silent pass': Rule 6 item 4 kept \
         the letter and lost the alert"
    );
}

/// **Acceptance red**: a financial operation (`CRITICAL`) + `RE=0` => must still need
/// human confirmation.
///
/// It covers the same path as the forensic criterion
/// `financial_operation_with_replay_disabled_must_not_auto_pass`, but that one only says
/// "it must not be Pass" while this one says "**it must be NeedHumanConfirm**".
/// => The former proves the defect is here; the latter pins the target shape.
///
/// Mutation: change `ReplayEnable::Disabled => RiskLevel::Medium` in `lib.rs:151` to
///           return `self.risk_level()`; this test turns green.
#[test]
fn financial_operation_with_replay_disabled_must_need_human_confirm() {
    let p = pfp(RiskLevel::Critical, OverrideFlag::Normal, ReplayEnable::Disabled);
    let d = decide(&p, &SecurityPolicy::default());

    assert_eq!(
        d,
        Decision::NeedHumanConfirm,
        "CRITICAL (financial / irreversible) + RE=0 => should still be NeedHumanConfirm. \
         Currently {d:?}"
    );
}

/// **Acceptance red**: `CATASTROPHIC` + `RE=0` => should still be `Reject` (the downgrade
/// must not pull it down).
///
/// Mutation: change `ReplayEnable::Disabled => RiskLevel::Medium` in `lib.rs:151` to
///           return `self.risk_level()`; this test turns green.
#[test]
fn catastrophic_with_replay_disabled_must_still_reject() {
    let p = pfp(RiskLevel::Catastrophic, OverrideFlag::Normal, ReplayEnable::Disabled);
    let d = decide(&p, &SecurityPolicy::default());

    assert_eq!(
        d,
        Decision::Reject,
        "CATASTROPHIC + RE=0 => should still be Reject. Currently {d:?} -- turning the \
         replay protection off must not make it more permissive"
    );
}
