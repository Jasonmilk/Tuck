//! 验收判据（**Acceptance**）—— 证明「目标状态尚未达成」
//!
//! ## 与取证判据的分工（阶段 A' · 第 3 项：拆文件）
//!
//! | | 断言形态 | 证明什么 |
//! |---|---|---|
//! | `financial_hitl_forensic.rs` | `assert_ne!(当前值, 不可接受值)` | 缺陷**在** |
//! | **本文件** | `assert_eq!(当前值, 目标值)` | 目标**未达成** |
//!
//! 本文件断言的是**裁决通过后应当成立的样子**。它们现在红，是因为目标还没达到；
//! 阶段 B 修完，这些应当转绿 —— 那时它们就从「验收判据」变成「回归网」。
//!
//! ⚠️ **本文件是全仓唯一允许断言「目标值」的地方。**
//! 若某条裁决被推翻，先改这里，再改取证判据。
//!
//! ## 纪律
//! 每条 `/// Mutation:` 写**「把哪行改成什么样」**，不写「改成什么方向」。

use tuck_core::{
    decide, Decision, OverrideFlag, PfpHeader, ReplayEnable, RiskLevel, SecurityPolicy,
};

fn pfp(risk: RiskLevel, of: OverrideFlag, re: ReplayEnable) -> PfpHeader {
    let mut bytes = [0xCF, 0x14, 0, 0];
    bytes[2] = (risk as u8) << 2;
    bytes[3] = (of as u8) << 1 | (re as u8) << 2;
    PfpHeader::from_bytes(bytes).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// ROAD-48 §2 正样本 —— **此前零判据覆盖**
// ═══════════════════════════════════════════════════════════════════════════

/// ★★ **ROAD-48 §2 · 验收红**
///
/// `HARD_OVERRIDE` + `CATASTROPHIC` + `Replay-Enable=0` ⇒ 应当是 **`Reject`**。
/// 当前实际是 **`Pass`**，且**此前没有任何判据覆盖这条路径**
/// （`lib.rs:513` 那条断言的是 `Pass`，不是 `Reject`）。
///
/// ### 为什么这比「降级」更严重（**两个维度的净损失**）
///
/// `Decision::HardOverridePass` 定义（`lib.rs:331-333`）：
/// 「unconditional pass with highest priority, **emergency signal to human in parallel**」。
/// ⇒ 它至少还**并行向人类发紧急信号**。
///
/// 而 Rule 6 的降级把它变成 `Pass`（`lib.rs:325`：frame continues to flow，无信号）。
/// ⇒ **净效果：从「最高优先级放行 + 并行告警」降成「静默放行」——
///    Rule 6 第 4 条确实『阻止了 hard override』，但代价是连告警一起丢了。**
///
/// ⇒ 这一句是"修它不是偏离规范，是恢复规范 stated intent 里本来就有的那半（告警）"。
///
/// Mutation: 把 `lib.rs:151` 的 `ReplayEnable::Disabled => RiskLevel::Medium`
///           改成返回 `self.risk_level()`，本条转绿。
#[test]
fn road48_hard_override_catastrophic_replay_disabled_must_reject() {
    let p = pfp(RiskLevel::Catastrophic, OverrideFlag::HardOverride, ReplayEnable::Disabled);
    let d = decide(&p, &SecurityPolicy::default());

    assert_eq!(
        d,
        Decision::Reject,
        "ROAD-48 §2：HO + CATASTROPHIC + RE=0 ⇒ Reject。当前是 {d:?} —— \
         降级把『放行+并行告警』变成了『静默放行』，Rule 6 第 4 条守住了字面，丢了告警"
    );
}

/// ★★ **验收红**：金融操作（`CRITICAL`）+ `RE=0` ⇒ 应当仍需人确认。
///
/// 与取证判据 `financial_operation_with_replay_disabled_must_not_auto_pass`
/// 覆盖同一条路径，但那条只说「不可以是 Pass」，这条说「**应当是 NeedHumanConfirm**」。
/// ⇒ 前者证明缺陷在，后者钉死目标形态。
///
/// Mutation: 把 `lib.rs:151` 的 `ReplayEnable::Disabled => RiskLevel::Medium`
///           改成返回 `self.risk_level()`，本条转绿。
#[test]
fn financial_operation_with_replay_disabled_must_need_human_confirm() {
    let p = pfp(RiskLevel::Critical, OverrideFlag::Normal, ReplayEnable::Disabled);
    let d = decide(&p, &SecurityPolicy::default());

    assert_eq!(
        d,
        Decision::NeedHumanConfirm,
        "CRITICAL(金融/不可逆) + RE=0 ⇒ 应仍是 NeedHumanConfirm。当前是 {d:?}"
    );
}

/// ★ **验收红**：`CATASTROPHIC` + `RE=0` ⇒ 应当仍是 `Reject`（不得被降级拉低）。
///
/// Mutation: 把 `lib.rs:151` 的 `ReplayEnable::Disabled => RiskLevel::Medium`
///           改成返回 `self.risk_level()`，本条转绿。
#[test]
fn catastrophic_with_replay_disabled_must_still_reject() {
    let p = pfp(RiskLevel::Catastrophic, OverrideFlag::Normal, ReplayEnable::Disabled);
    let d = decide(&p, &SecurityPolicy::default());

    assert_eq!(
        d,
        Decision::Reject,
        "CATASTROPHIC + RE=0 ⇒ 应仍是 Reject。当前是 {d:?} —— 关掉重放保护不该让它更宽松"
    );
}
