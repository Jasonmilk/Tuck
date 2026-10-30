# EXPECTED-RED · 九条判据在当前版本必须红

**为什么存在这份清单**：`financial_hitl_forensic.rs` / `financial_hitl_acceptance.rs`
是 YB-rust 交来的**取证 + 验收判据**，它们描述的是「修完之后必须成立的样子」。
现在的红**不是回归、不是环境问题，是缺陷本身**。

**⇒ 因此 `tools/verify.sh` 现在是红的，CI 的 `gate` 也是红的。这是可归因的红。**

## 变更纪律

- 这份清单**只能缩短，不能变长**。往这里加一行 = 承认「又有一条判据在证明缺陷」，
  必须同时给出对应的修复裁决编号。
- 清单里的判据**不许 `#[ignore]`、不许改写断言**。它们红了才是工作。
- 判据**转绿那天**，删掉对应条目；如果它是被改 Weak 才转绿的，那不是转绿，是关掉了判据。

## 当前清单（9 条，2026-10-30）

`crates/tuck-core/tests/financial_hitl_forensic.rs`（5 passed / 6 failed）

| 判据 | 证明的缺陷 | 根因行 |
|---|---|---|
| `financial_operation_with_replay_disabled_must_not_auto_pass` | CRITICAL + RE=0 ⇒ `Pass`，HITL 门从未走过 | `src/lib.rs:151` |
| `replay_disabled_must_not_turn_catastrophic_reject_into_pass` | 关掉重放保护让最危险档**更宽松**（Reject → Pass） | `src/lib.rs:151` |
| `break_glass_must_not_be_enabled_by_default` | `SecurityPolicy::default()` 开着 break-glass | `src/lib.rs:364` |
| `break_glass_must_not_be_enabled_in_policy_config_default` | **第二个生产默认**（TOML 路径）也开着 | `src/policy.rs:285` |
| `no_test_fixture_may_encode_break_glass` | `hot_reload.rs` 两处夹具写死了 `hard_override_pass` | `src/hot_reload.rs:327` / `:343` |
| `unanswered_must_not_be_recorded_as_timed_out` | 「没人应答」被记成「超时」（两义合一） | `src/hitl.rs` `ConfirmStatus` |

`crates/tuck-core/tests/financial_hitl_acceptance.rs`（0 passed / 3 failed）

| 判据 | 目标值 |
|---|---|
| `road48_hard_override_catastrophic_replay_disabled_must_reject` | HO + CATASTROPHIC + RE=0 ⇒ `Reject`（今天 `Pass`，净损失「放行+并行告警」） |
| `financial_operation_with_replay_disabled_must_need_human_confirm` | CRITICAL + RE=0 ⇒ `NeedHumanConfirm` |
| `catastrophic_with_replay_disabled_must_still_reject` | CATASTROPHIC + RE=0 ⇒ `Reject` |

**必须保持绿的 5 条**（防修法过头）：`critical_with_replay_enabled_still_needs_human_confirm`
· `low_and_medium_risk_stay_pass` · `genuine_medium_is_unaffected_by_the_downgrade_fix`
· `hard_override_path_is_reachable_when_replay_enabled` · `the_two_defaults_must_not_drift_apart`

## 归属

- 缺陷登记与五条裁决：`docs/hitl/CI144-REGISTER.md`（YB 阶段 A/A' 报告）
- 台账一条：`helix-mind/docs/helixECO/consensus-ledger.md` C-032（英文化）/ C-033（本清单）
- reopen：阶段 B 落地时删条目；若阶段 B 被推翻，本清单改为「作废」而不是「延长」
