# Tuck 开发导航牌（PLAN）

> **版本**：v0.3.0（P2 策略引擎，2026-08-29）
> **状态**：🚧 P2 — 策略引擎（进行中）
> **上一阶段**：P1 — 核心骨架完善 ✅ 已完成（见 GROWTH.md，28 tests + 11 benchmarks，p99=322.89ps）
> **分支**：rs
> **所属方法论**：phyt-DNA v1.0（PLAN 动态流转闭环，方法论锚点项目 https://github.com/Jasonmilk/phyt-DNA）
> **规则**：本文件只含当前阶段 + 下一阶段预览 + 阶段总览地图。完成阶段 → GROWTH.md。总行数 ≤150，超出触发历史迁移。

---

## 1. 当前阶段：P2 — 策略引擎

> **状态**：🚧 进行中。
> **前置依赖**：P1 核心骨架 ✅（decide() p99=322.89ps，28 tests，SAP 可选增强）。
> **目标**：Risk-Level 策略配置文件、HITL 执行闸、CATASTROPHIC 硬覆盖完整实现、策略热加载、策略版本管理。

### 1.1 目标

| 任务 | 内容 | 入口 | 状态 |
|---|---|---|---|
| T1 | 策略配置文件（YAML/TOML）+ 反序列化 | serde + config crate | ⏳ |
| T2 | HITL 执行闸（NeedHumanConfirm → 确认通道 → 超时 Reject） | tokio + 异步通道 | ⏳ |
| T3 | CATASTROPHIC 硬覆盖完整实现（紧急信号 + 并行人类通知） | tokio::sync::Notify + 广播 | ⏳ |
| T4 | 策略热加载（不重启更新策略）+ 策略版本管理 | 文件监听 + 原子交换 | ⏳ |

### 1.2 核心承诺状态

| 承诺 | 状态 | 落地阶段 |
|---|---|---|
| 1 只读 4 字节，亚微秒级决策 | ✅ P1 验证（p99=322.89ps） | P1 |
| 2 fail-closed，永不放行未知 | ✅ P1 验证（≥12 异常类别 100% Reject） | P1 |
| 3 凭证永不在组件内存中 | ⏳ | P3 |
| 4 每一次决策都不可篡改地记录 | 🚧 P2 部分（策略版本记录）→ P4 完整 | P2/P4 |

### 1.3 入口 ADR

- **ADR-0001**：Tuck Rust 重构 + 思想重新对齐（Active）
- **ADR-0002**：PFP 依赖策略 — 保留本地零拷贝实现（Active）
- **P2 新增 ADR 候选**：策略配置格式选择（YAML vs TOML）、HITL 通道设计、策略热加载机制

### 1.4 验收标准

- T1：策略文件可加载，Risk-Level → Decision 映射可配置，默认策略与硬编码一致
- T2：NeedHumanConfirm 决策触发确认请求，确认后 Pass，超时后 Reject，单元测试覆盖
- T3：CATASTROPHIC + Override → HardOverridePass + 紧急信号 + 并行人类通知，优先级高于常规负载
- T4：策略文件修改后自动热加载（≤1s），不中断正在处理的帧；策略版本号递增，审计日志记录策略版本
- `cargo test --workspace` 全绿 + 0 warning
- 硬实时路径（decide()）不受策略热加载影响（p99 仍 <1μs）

### 1.5 下一阶段预览：P3 — 凭证物理注入

- identity_label → 明文凭证映射（CredentialStore trait）
- 物理边缘注入（出网前注入，注入后 zeroize）
- HSM/TPM 支持（生产环境凭证存储）
- 凭证零化验证（内存审查测试）
- CredentialStore 多种实现（文件/HSM/Vault）

---

## 2. 阶段总览（地图，不展开）

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 方法论初始化 + Rust 项目骨架 | ✅ 已完成 |
| P1 | 核心骨架（PFP 读取 + 硬实时决策 + fail-closed + SAP 可选增强） | ✅ 已完成 |
| **P2** | **策略引擎（Risk-Level 策略配置 + HITL 执行闸 + CATASTROPHIC 硬覆盖）** | **🚧 进行中** |
| P3 | 凭证物理注入（identity_label → 明文凭证 + 零化 + HSM/TPM） | ⏳ 规划 |
| P4 | 全息审计（SHA-256 链式日志 + WORM 存储 + 查询 API） | ⏳ 规划 |
| P5 | 传输层集成（CI-144 帧代理/中间件 + HTTP/gRPC 接入） | ⏳ 规划 |
| P6 | 生态联调（与 Anaphase/Tentacle/Cellrix 端到端联调） | ⏳ 规划 |

---

## 3. 活跃决策与契约指针（不展开）

| 项 | 指针 |
|---|---|
| 核心承诺 | VISION.md 第四节（4 条承诺） |
| 特有铁律 | DNA.md 第五节（5 条：PFP 只读/fail-closed/凭证/审计/无分配） |
| CI-144 PFP 规范 | https://github.com/CommonIntents/PFP-xCF14 |
| BIND-19 参考实现 | https://github.com/CommonIntents/BIND-19 (v2.0-rc.1) |
| 方法论 | phyt-DNA v1.0 (https://github.com/Jasonmilk/phyt-DNA) |
| Python beta 历史 | archive/python-beta/（哲学不成熟，仅供考古） |

---

## 4. 文档生态 SOP

PLAN 是导航牌不是历史档案；阶段收尾时（收尾 SLA：24h）完成记录追加 GROWTH.md 并从 PLAN 移除；GROWTH ≤3 条超则归档；PLAN ≤150 行超则触发历史迁移。提交信息必须包含 ADR 关联 `(ADR-NNNN §Tx)`。详见 `docs/DNA.md`「文档生态 SOP」和 `docs/RNA.md`「加载协议」。
