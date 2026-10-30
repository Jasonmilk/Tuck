//! 取证判据（**Forensic**）—— 证明「缺陷当前正在生效」
//!
//! ## 与验收判据的分工（阶段 A' · 第 3 项：拆文件）
//!
//! | | 断言形态 | 证明什么 | 修复后 |
//! |---|---|---|---|
//! | **本文件（取证）** | `assert_ne!(当前值, 不可接受值)` | 缺陷**在** | 转绿 |
//! | `financial_hitl_acceptance.rs` | `assert_eq!(当前值, 目标值)` | 目标**未达成** | 转绿 |
//!
//! 拆开的理由：混在一处会让阶段 B 的归因混乱——「这条红是因为缺陷还在，
//! 还是因为目标没达到」需要看断言形态才能分。
//!
//! ## 纪律（阶段 A' · 第 1 项的教训）
//!
//! **本文件不含任何「断言当前行为」的测试。**
//! 只断言「不可以是 X」，从不断言「现在是 X 且将是 X」——后者是反向路标。
//! 需要记录当前行为的，写进 `CI144-REGISTER.md`，不写成断言。
//!
//! ## Mutation 措辞纪律（阶段 A' · 第 7 项）
//!
//! 每条 `/// Mutation:` 写**「把哪行改成什么样」**，不写「改成什么方向」。

use std::time::Duration;

use tuck_core::hitl::{ConfirmStatus, HumanConfirmGate};
use tuck_core::policy::PolicyConfig;
use tuck_core::{
    decide, Decision, OverrideFlag, PfpHeader, ReplayEnable, RiskLevel, SecurityPolicy,
};

/// 复刻 `lib.rs:468` 的 `make_pfp`（测试夹具，不改动被检件）。
/// 位域照 PFP README Byte Layout：Byte2 Bits2-3 = Risk-Level；Byte3 Bit1 = Override-Flag，
/// Bit2 = Replay-Enable。
fn pfp(risk: RiskLevel, of: OverrideFlag, re: ReplayEnable) -> PfpHeader {
    let mut bytes = [0xCF, 0x14, 0, 0];
    bytes[2] = (risk as u8) << 2;
    bytes[3] = (of as u8) << 1 | (re as u8) << 2;
    PfpHeader::from_bytes(bytes).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// 缺口 3 · 降级 ⇒ 金融操作绕过 HITL
// ═══════════════════════════════════════════════════════════════════════════

/// ★★ **主判据 · 取证红**
///
/// 金融操作 = `CRITICAL(2)` + `Replay-Enable=0` ⇒ 当前得到 `Pass`。
///
/// 为什么 `Pass` 不可接受：`Decision::NeedHumanConfirm` 语义是
/// 「暂停，请求人类确认；确认→Pass，超时→Reject」。直接返回 `Pass`
/// ⇒ **HITL 这道门根本没有被走过**。
///
/// Mutation: 把 `lib.rs:151` 的 `ReplayEnable::Disabled => RiskLevel::Medium`
///           改成返回 `self.risk_level()`，本条转绿。
#[test]
fn financial_operation_with_replay_disabled_must_not_auto_pass() {
    let p = pfp(RiskLevel::Critical, OverrideFlag::Normal, ReplayEnable::Disabled);
    let d = decide(&p, &SecurityPolicy::default());

    assert_ne!(
        d,
        Decision::Pass,
        "CRITICAL(金融/不可逆) + Replay-Enable=0 ⇒ 当前是 {d:?}。\
         降级把需人确认的动作变成了直接放行 —— HITL 未被走过。"
    );
}

/// ★ **取证红**：`CATASTROPHIC` 在 replay-disabled 下被**从 Reject 降到 Pass**。
///
/// **关掉重放保护，让最危险的类别变得更宽松。**
///
/// Mutation: 把 `lib.rs:151` 的 `ReplayEnable::Disabled => RiskLevel::Medium`
///           改成返回 `self.risk_level()`，本条转绿。
#[test]
fn replay_disabled_must_not_turn_catastrophic_reject_into_pass() {
    let off = pfp(RiskLevel::Catastrophic, OverrideFlag::Normal, ReplayEnable::Disabled);
    assert_ne!(
        decide(&off, &SecurityPolicy::default()),
        Decision::Pass,
        "关掉重放保护后 CATASTROPHIC 从 Reject 变成了 Pass —— 补偿措施让最危险的类别更宽松，\
         与 PFP Rule 6 第 4 条『prevents high-risk physical attacks via replay』方向相反"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 缺口 4 · break-glass 在默认路径上开着
// ═══════════════════════════════════════════════════════════════════════════

/// ★ **取证红**：`SecurityPolicy::default()` 的 `catastrophic_override` 是 `HardOverridePass`。
///
/// 默认路径 ⇒ 不配置就等于启用。三次裁决已拒绝它
/// （ADR-0054 §五.2 / ROAD-18 B-4 / ADR-0004 D7）。
///
/// Mutation: 把 `lib.rs:364` 的 `catastrophic_override: Decision::HardOverridePass`
///           改成 `Decision::Reject`，本条转绿。
#[test]
fn break_glass_must_not_be_enabled_by_default() {
    let pol = SecurityPolicy::default();
    assert_ne!(
        pol.catastrophic_override,
        Decision::HardOverridePass,
        "默认策略把 break-glass 开成了 HardOverridePass —— 不配置即启用，\
         且已被 ADR-0054 §五.2 / ROAD-18 B-4 / ADR-0004 D7 三次拒绝"
    );
}

/// ★ **取证红（阶段 A' 第 4 项 · 新增）**：**第二处生产默认**。
///
/// 阶段 A 报告只判了 `lib.rs:364` 的 `SecurityPolicy::default()`，
/// **漏了 `policy.rs:285` 的 `PolicyConfig::default()`** —— 那是 TOML 配置路径的默认值，
/// 与 `SecurityPolicy::default()` 是**两条独立的默认源**。
///
/// ⇒ 只改 `lib.rs:364` 而漏掉这里 ⇒ 走配置路径的部署仍然开着 break-glass。
///
/// Mutation: 把 `policy.rs:285` 的 `catastrophic_override: DecisionConfig::HardOverridePass`
///           改成 `DecisionConfig::Reject`，本条转绿。
#[test]
fn break_glass_must_not_be_enabled_in_policy_config_default() {
    let pol = PolicyConfig::default().to_policy();
    assert_ne!(
        pol.catastrophic_override,
        Decision::HardOverridePass,
        "PolicyConfig::default()（policy.rs:285）是【第二处】生产默认，\
         同样开着 break-glass。TOML 配置路径与 SecurityPolicy::default() 是两条独立默认源，\
         只改一处等于没改"
    );
}

/// ★ **取证红（阶段 A' 第 4 项 · 新增）**：**测试夹具里写死 break-glass**。
///
/// `hot_reload.rs:327`（`default_policy_toml`）与 `:343`（`strict_policy_toml`）
/// 两处把 `catastrophic_override = "hard_override_pass"` 写进了夹具。
///
/// **定性（修正阶段 A 报告的说法）**：这两处在 `#[cfg(test)] mod tests` 内
/// （`hot_reload.rs:302`），**不是生产默认**，是夹具。
/// ⇒ 阶段 A 报告把它们算作「默认开着的地方」是**我数错了**（见 `CI144-REGISTER.md` 的更正）。
///
/// 但它们仍须被判：改生产默认值时若不同步改这两处，
/// ⇒ 热加载测试会继续断言一个**已被禁止的值**，成为残留路标。
///
/// Mutation: 把 `hot_reload.rs` 里两处 `hard_override_pass` 字面量删掉或改成别的决策，
///           本条转绿。
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
        "hot_reload.rs 的夹具里仍有 break-glass 字面量（改动生产默认值时必须同步改这里）：\n{}",
        hits.iter()
            .map(|(n, l)| format!("  行 {n}: {}", l.trim()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 缺口 · 无人应答被表达成超时
// ═══════════════════════════════════════════════════════════════════════════

/// ★★ **取证红 · 无人应答不得被表达成超时**
///
/// 构造 gate，`request()` 后**既不 confirm 也不 reject**（= 无人应答），
/// 超时后 `history()` 记的是 `TimedOut`。
///
/// 为什么这是缺陷：`ConfirmStatus::TimedOut` 语义是「有人，但没在时限内答复」；
/// 本场景是「**根本没有应答者**」。
/// ⇒ 两个事实折叠成一个值 ⇒ 与 anaphase 的 `ApprovalOutcome` 四值闭集
/// （`AllowedOnce/Rejected/Cancelled/Unavailable`）不同形。
///
/// ⚠️ **本条的具名局限**（阶段 B 前置，见 `CI144-REGISTER.md` §应答者注册）：
/// 单纯加枚举变体**修不好这条** —— `request()` 返回的 rx 被丢弃与否，
/// gate 无从区分「有人拿着 rx 没回」与「根本没人拿 rx」。
/// ⇒ 阶段 B 之前**必须先有应答者注册的设计**，否则 Pi 会做成恒绿假实现
/// （「有 rx 就算有人」）。
///
/// Mutation: 给 `ConfirmStatus` 加 `Unavailable` 变体，并让 `request()` 在
///           **无应答者注册**时落该态而非 `TimedOut`，本条转绿。
#[tokio::test]
async fn unanswered_must_not_be_recorded_as_timed_out() {
    let gate = HumanConfirmGate::new(Duration::from_millis(100));
    let (_id, _rx) = gate
        .request("Critical", "Executive", "wire 100k to beneficiary")
        .await;

    // 无人应答：不 confirm、不 reject。等超时任务跑完。
    tokio::time::sleep(Duration::from_millis(250)).await;

    let history = gate.history().await;
    assert_eq!(history.len(), 1, "应当只有一条：那个无人应答的请求");
    assert_ne!(
        history[0].status,
        ConfirmStatus::TimedOut,
        "'无人应答' 与 '有人没及时答' 是两个事实，当前都被记成 TimedOut。\
         Tuck 生产上 confirm() 不可达 ⇒ 无人应答是常态，却被表达成超时（= 假装有人在听）"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 反样本（**必须保持绿**）—— 防修法过头 / 防误伤
// ═══════════════════════════════════════════════════════════════════════════

/// 反样本①：`CRITICAL` + `RE=1` ⇒ `NeedHumanConfirm`（修前修后都须成立）。
#[test]
fn critical_with_replay_enabled_still_needs_human_confirm() {
    let p = pfp(RiskLevel::Critical, OverrideFlag::Normal, ReplayEnable::Enabled);
    assert_eq!(
        decide(&p, &SecurityPolicy::default()),
        Decision::NeedHumanConfirm,
        "CRITICAL + RE=1 ⇒ NeedHumanConfirm（基线，修前修后都须成立）"
    );
}

/// 反样本②：低风险不被误伤。
#[test]
fn low_and_medium_risk_stay_pass() {
    let low = pfp(RiskLevel::Low, OverrideFlag::Normal, ReplayEnable::Enabled);
    assert_eq!(decide(&low, &SecurityPolicy::default()), Decision::Pass);

    let med = pfp(RiskLevel::Medium, OverrideFlag::Normal, ReplayEnable::Enabled);
    assert_eq!(decide(&med, &SecurityPolicy::default()), Decision::Pass);
}

/// 反样本③：**原生** MEDIUM（非降级所得）保持 Pass。
/// 与判据 1 的差别仅在「降没降级」⇒ 确保修法针对**降级这个动作**，
/// 而不是一刀切把 `medium` 改掉。
#[test]
fn genuine_medium_is_unaffected_by_the_downgrade_fix() {
    let m = pfp(RiskLevel::Medium, OverrideFlag::Normal, ReplayEnable::Disabled);
    assert_eq!(
        decide(&m, &SecurityPolicy::default()),
        Decision::Pass,
        "原生 MEDIUM + RE=0 仍是 MEDIUM ⇒ Pass。修法只针对【降级】本身"
    );
}

/// 反样本④：**CATASTROPHIC + HO + RE=1** 落到 `policy.catastrophic_override`。
/// 本条**不断言**那个值是否正确（那是缺口 4 的裁决范围），
/// 只钉住「RE=1 时 HO 路径确实被走到」——作为验收判据的对照基线。
#[test]
fn hard_override_path_is_reachable_when_replay_enabled() {
    let p = pfp(RiskLevel::Catastrophic, OverrideFlag::HardOverride, ReplayEnable::Enabled);
    let d = decide(&p, &SecurityPolicy::default());
    assert_eq!(
        d,
        SecurityPolicy::default().catastrophic_override,
        "RE=1 时 HO+CATASTROPHIC 应落到 policy.catastrophic_override（对照基线）"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 守卫 · 唯一事实来源（SSOT）—— 本条当前【绿】，守的是未来
// ═══════════════════════════════════════════════════════════════════════════

/// 守卫（当前绿）：**两份默认值必须逐字段相等**。
///
/// 存在两份 `impl Default`：
///   - `lib.rs:364`  `impl Default for SecurityPolicy`   （运行时层 · 生产可达，main.rs:59）
///   - `policy.rs:285` `impl Default for PolicyConfig`   （配置层 · TOML 形状）
///
/// 两份都写死了同一组 6 个字段 ⇒ **SSOT 分裂**：改一处漏一处，两处默认值就会漂。
/// 修法（**勿增实体**）：让运行时层成为配置层的**投影**
/// （`SecurityPolicy::default() = PolicyConfig::default().to_policy()`），
/// 与 anaphase `ACTION_WORDS` + `role_words()` 同形。
///
/// 本条现在是绿的（两份恰好相等）⇒ 它是**漂移检测器**，不是缺陷判据：
/// 一旦有人只改了一处，它立刻红。
///
/// Mutation: 改 `lib.rs:364` 或 `policy.rs:285` 其中**一处**而不改另一处 ⇒ 本条转红。
#[test]
fn the_two_defaults_must_not_drift_apart() {
    let a = SecurityPolicy::default();
    let b = PolicyConfig::default().to_policy();

    let fields: Vec<(&str, Decision, Decision)> = vec![
        ("low", a.low, b.low),
        ("medium", a.medium, b.medium),
        ("critical", a.critical, b.critical),
        ("catastrophic", a.catastrophic, b.catastrophic),
        ("catastrophic_override", a.catastrophic_override, b.catastrophic_override),
    ];
    for (name, x, y) in fields {
        assert_eq!(
            format!("{x:?}"),
            format!("{y:?}"),
            "默认值在 {name} 上分裂了：SecurityPolicy::default() 与 \
             PolicyConfig::default().to_policy() 不一致 —— 改一处必须改另一处，\
             或让其中一份成为另一份的投影"
        );
    }
    assert_eq!(
        a.external_additional_check, b.external_additional_check,
        "external_additional_check 同样分裂了"
    );
}
