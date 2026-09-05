# ADR-0003: Cellrix 状态流 — 决策状态查询接口与文档对齐

> **状态**：Active
> **日期**：2026-09-05
> **决策者**：Jasonmilk / CommonIntents
> **关联阶段**：P6-T5（Cellrix 联调）＋ P6/P7 文档对齐
> **前置 ADR**：ADR-0001（Rust 重构 + 思想重新对齐）、ADR-0002（PFP 依赖策略）

---

## 背景（Context）

Tuck P6-T5 的目标：**Tuck 决策状态在 Cellrix 实时展示（Pass/Reject/HITL/CATASTROPHIC）**，入口形态为"状态流"。

**物理事实核验（以 git 与代码为准，PLAN 状态滞后于代码）**：

- P6-T1..T4 与 P7-T1..T4 均已实现并推送（commit `613051d`（SAP 对接：PAH 签名验证 + LRU 防重放缓存 + decide_with_sap）→ `a087979`（Mind 联调）→ `0842a0b`（Anaphase 联调）→ `b379034`（Tentacle 联调）→ `0189549`/`3f7a279`/`1d2e10f`/`0b42e0a`（P7 配置/日志/监控/部署））
- **P6-T5 是 P6 唯一代码缺口**：无对应 commit，代码中无 Cellrix 消费引用
- 文档全面滞后：PLAN 停在 v0.7.0（P6 进行中，T1-T5 全标 ⏳）；GROWTH 只记录到 P5；README 测试数 310 未含 P7 增量
- 现有可复用资产：`Metrics`（原子计数器：decisions_pass/reject/hitl/hard_override + risk_low/medium/critical/catastrophic，**只有写入无读取 API**）；`AuditLog`（P4 内存链式审计：AuditEntry 含 timestamp/decision/risk_level/modality/source 等全部字段，有 latest/get/iter）；`AuditStore`（WORM 持久化 + AuditQuery）
- 310 tests passed / 0 failed（当前基线）

## 决策（Decisions）

### D1: 状态流 = 拉模式查询接口，不做推送/订阅

Tuck 侧交付 `StatusProvider` trait（`summary()` + `recent_decisions(limit)`），Cellrix 按需拉取。**不做**推送通道/订阅发布（Tuck 是闸门，不承担通知义务；按需驱动原则：展示层需要时才查询，Tuck 零主动开销）。

### D2: 数据源复用，零新存储

- `DecisionSummary`（实时快照）：从 `Metrics` 聚合——O(1)、原子、与 Tuck 运行期真实决策一致
- `DecisionEvent`（单条）：从 `AuditLog` 最近条目投影——复用 P4 审计链，**不新建事件存储/不新增写路径**（勿增实体）

### D3: 事件投影裁剪

`DecisionEvent` 只暴露 Cellrix 展示所需字段（timestamp / decision / risk_level / modality / source），不持有完整 `AuditEntry`（按需加载：展示层不需要 hash 链与身份标签；防数据膨胀）。

### D4: Metrics 只读 getter 按需添加

`Metrics` 增加 `decision_counts()` / `risk_counts()` 只读聚合（现有 8 个原子计数器 → 结构化计数），**不改任何写入路径**（observe_* 保持原样，向后兼容 310 测试）。

### D5: Cellrix 消费 = 跨仓库债

Tuck 只提供接口与实现；Cellrix 侧按 `StatusProvider` 消费展示（Pass/Reject/HITL/CATASTROPHIC 状态渲染）属 Cellrix 仓库工作，记入跨仓库相邻债（与 Anaphase seen_entropy_bloom 同理——本仓库交付协议面，消费面留给对端）。

### D6: 文档对齐为本次强制交付

PLAN（P6 全绿 + P7 完成标记）、GROWTH（补 P6/P7 健康快照）、README（测试数与特性同步）在本次一并更新——文档滞后于代码本身就是违反方法论的健康问题，必须修复。

## 备选方案与拒绝理由

| 备选 | 拒绝理由 |
|---|---|
| 推送/订阅状态流（channel/broadcast） | Tuck 无通知义务；增加运行期状态与并发复杂度；Cellrix 按需拉取已满足展示需求 |
| 新建独立决策事件存储 | 与 P4 审计链重复——AuditLog 已有全部字段；新建即违背"极致复用/勿增实体" |
| 直接暴露 Metrics 原子计数 + AuditEntry 原始结构 | 破坏封装：展示层不该接触内部计数结构与审计链字段；投影裁剪是接口职责 |
| 通过 export_prometheus 文本解析读数 | 文本解析脆弱、非类型安全；只读 getter 是确定性的类型化接口 |

## 后果（Consequences）

**正面**：
- P6 五任务全绿，Tuck 生态联调闭环（协议家族 → Mind → Anaphase → Tentacle → Cellrix）
- 状态查询 O(1) 实时（Metrics 原子计数），零新增存储与写路径
- 展示层与内部结构解耦（StatusProvider 是稳定接口，内部实现可演进）
- 文档对齐，方法论闭环恢复

**负面/代价**：
- Metrics 增加两个只读结构（DecisionCounts/RiskCounts）——必要的最小接口增量
- Cellrix 侧消费未在本仓库完成（跨仓库债，需 Cellrix 仓库推进）

**风险与对策**：
- 计数与审计链可能短时不一致（Metrics 更新与 AuditLog append 非原子）→ 接受：两者服务不同目的（实时计数 vs 可验证历史），展示层语义明确为"运行期累计快照 + 最近事件"
- Cellrix 尚未实现 CI-144 消费 → 本 ADR 只交付接口面，不虚构消费端

## 实现要点（与 P6-T5 映射）

| 决策 | 落点 | 状态 |
|---|---|---|
| D1 | `status.rs`：`StatusProvider` trait（summary + recent_decisions） | 本次实现 |
| D2 | `DecisionSummary` 聚合 Metrics；`DecisionEvent` 投影 AuditLog | 本次实现 |
| D3 | 投影裁剪（5 字段） | 本次实现 |
| D4 | `metrics.rs`：DecisionCounts/RiskCounts + 只读 getter | 本次实现 |
| D5 | 跨仓库债记录（Cellrix 消费） | 本次记录 |
| D6 | PLAN/GROWTH/README/ECOSYSTEM 对齐 | 本次交付 |

## 一句话总结

> 状态流不是广播，是窗口——Cellrix 想看时打开，Tuck 的计数与审计链就是窗外的风景；
> 本仓库交付窗口本身（StatusProvider），风景的陈列是 Cellrix 的事。
