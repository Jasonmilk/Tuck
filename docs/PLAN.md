# Tuck 开发导航牌（PLAN）

> **版本**：v0.5.0（P4 全息审计，2026-08-29）
> **状态**：🚧 P4 — 全息审计（进行中）
> **上一阶段**：P3 — 凭证物理注入 ✅ 已完成（见 GROWTH.md，123 tests，identity_label + 物理边缘注入 + AES-GCM 加密存储 + HSM/TPM trait）
> **分支**：rs
> **所属方法论**：phyt-DNA v1.0（PLAN 动态流转闭环，方法论锚点项目 https://github.com/Jasonmilk/phyt-DNA）
> **规则**：本文件只含当前阶段 + 下一阶段预览 + 阶段总览地图。完成阶段 → GROWTH.md。总行数 ≤150，超出触发历史迁移。

---

## 1. 当前阶段：P4 — 全息审计

> **状态**：🚧 进行中。
> **前置依赖**：P3 凭证物理注入 ✅（123 tests，CredentialStore + 物理边缘注入 + Zeroizing + FileCredentialStore + HSM/TPM trait）。
> **目标**：SHA-256 链式审计日志、WORM 存储、审计查询 API、篡改检测、与 HITL/CATASTROPHIC/策略重载历史整合。

### 1.1 目标

| 任务 | 内容 | 入口 | 状态 |
|---|---|---|---|
| T1 | 审计日志结构（SHA-256 链式，每条包含上一条哈希） | sha2 + serde | ⏳ |
| T2 | WORM 追加写存储（文件追加，不可修改/删除） | tokio::fs + 原子追加 | ⏳ |
| T3 | 审计查询 API（按时间范围/Risk-Level/决策类型查询） | 内存索引 + 文件扫描 | ⏳ |
| T4 | 篡改检测（验证哈希链完整性）+ 与现有历史整合 | sha2 验证 | ⏳ |

### 1.2 核心承诺状态

| 承诺 | 状态 | 落地阶段 |
|---|---|---|
| 1 只读 4 字节，亚微秒级决策 | ✅ P1 验证（p99=322.89ps） | P1 |
| 2 fail-closed，永不放行未知 | ✅ P1 验证 + P2 HITL 超时自动 Reject | P1/P2 |
| 3 凭证永不在组件内存中 | ✅ P3 实现（identity_label + 物理边缘注入 + Zeroizing） | P3 |
| 4 每一次决策都不可篡改地记录 | 🚧 P4 实现（SHA-256 链式日志 + WORM 存储） | P4 |

### 1.3 入口 ADR

- **ADR-0001**：Tuck Rust 重构 + 思想重新对齐（Active）
- **ADR-0002**：PFP 依赖策略 — 保留本地零拷贝实现（Active）
- **P4 新增 ADR 候选**：审计日志格式选择、WORM 存储实现、哈希链验证策略

### 1.4 验收标准

- T1：审计日志结构完整，每条包含前一条哈希（SHA-256），链式结构可验证
- T2：WORM 存储实现追加写，不可修改/删除已有记录，崩溃后可恢复
- T3：查询 API 支持按时间范围、Risk-Level、决策类型筛选，分页
- T4：篡改检测可识别哈希链断裂，与 HITL/CATASTROPHIC/重载历史整合
- `cargo test --workspace` 全绿 + 0 warning
- 审计写入不影响硬实时路径（decide() 仍 p99 <1μs，审计异步写入）

### 1.5 下一阶段预览：P5 — 传输层集成

- CI-144 帧代理/中间件（Tuck 作为 BIND-19 帧的拦截层）
- HTTP/gRPC 接入（Tuck 作为 HTTP 代理或 gRPC 拦截器）
- 出网凭证注入集成（与 P3 物理边缘注入对接）
- 性能压测（高并发下的决策延迟 + 审计写入吞吐量）

---

## 2. 阶段总览（地图，不展开）

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 方法论初始化 + Rust 项目骨架 | ✅ 已完成 |
| P1 | 核心骨架（PFP 读取 + 硬实时决策 + fail-closed + SAP 可选增强） | ✅ 已完成 |
| P2 | 策略引擎（策略配置 + HITL 执行闸 + CATASTROPHIC 硬覆盖 + 热加载） | ✅ 已完成 |
| P3 | 凭证物理注入（identity_label → 明文凭证 + zeroize + HSM/TPM） | ✅ 已完成 |
| **P4** | **全息审计（SHA-256 链式日志 + WORM 存储 + 查询 API）** | **🚧 进行中** |
| P5 | 传输层集成（CI-144 帧代理/中间件 + HTTP/gRPC 接入） | ⏳ 规划 |
| P6 | 生态联调（与 Anaphase/Tentacle/Cellrix 端到端联调） | ⏳ 规划 |

---

## 3. 活跃决策与契约指针（不展开）

| 项 | 指针 |
|---|---|
| 核心承诺 | VISION.md 第四节（4 条承诺） |
| 特有铁律 | DNA.md 第五节（5 条：PFP 只读/fail-closed/凭证/审计/无分配） |
