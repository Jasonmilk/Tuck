# EXPECTED-RED · 当前只剩 1 条

**2026-11-01 更新**：A1/A2/A3 落地后，9 条判据里 **8 条已转绿并从名单移除**（同批，
见 `tools/expected-red.list`）。剩下的 1 条属于 B2，不在 A 组范围。

| 判据 | 证明的缺陷 | 根因行 | 归属 |
|---|---|---|---|
| `unanswered_must_not_be_recorded_as_timed_out` | 「没人应答」被记成「超时」（两义合一） | `src/hitl.rs` `ConfirmStatus` | B2（`NoResponder` + 应答者注册） |

**已转绿（不再是预期红，保留在此作为历史）**：
`financial_operation_with_replay_disabled_must_not_auto_pass` ·
`replay_disabled_must_not_turn_catastrophic_reject_into_pass` ·
`break_glass_must_not_be_enabled_by_default` ·
`break_glass_must_not_be_enabled_in_policy_config_default` ·
`no_test_fixture_may_encode_break_glass` ·
`road48_hard_override_catastrophic_replay_disabled_must_reject` ·
`financial_operation_with_replay_disabled_must_need_human_confirm` ·
`catastrophic_with_replay_disabled_must_still_reject`

⇒ 它们从「取证红」变成了**回归网**：任何一次让它们变红的改动都是真回归，而不再是预期。

## 变更纪律（不变）

- 清单**只能缩短**。加一行 = 承认又一条判据在证明缺陷，必须同时给修复裁决编号。
- 清单里的判据**不许 `#[ignore]`、不许改弱断言**。
- 转绿必须与「从名单移除」**同一提交**，且该提交要触碰它记录的根因文件
  （`expected-red.py` R2 会点名"改测试而非改代码"）。
