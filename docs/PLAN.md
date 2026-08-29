# Tuck 开发导航牌（PLAN）

> **版本**：v0.6.0（P5 传输层集成，2026-08-29）
> **状态**：🚧 P5 — 传输层集成（进行中）
> **上一阶段**：P4 — 全息审计 ✅ 已完成（见 GROWTH.md，173 tests，SHA-256 链式日志 + WORM 存储 + 查询 API + 篡改检测）
> **分支**：rs
> **所属方法论**：phyt-DNA v1.0（PLAN 动态流转闭环，方法论锚点项目 https://github.com/Jasonmilk/phyt-DNA）
> **规则**：本文件只含当前阶段 + 下一阶段预览 + 阶段总览地图。完成阶段 → GROWTH.md。总行数 ≤150，超出触发历史迁移。

---

## 1. 当前阶段：P5 — 传输层集成

> **状态**：🚧 进行中。
> **前置依赖**：P4 全息审计 ✅（173 tests，4 条核心承诺全部实现）。
> **目标**：CI-144 帧代理/中间件、HTTP/gRPC 接入、出网凭证注入集成、性能压测。

### 1.1 目标

| 任务 | 内容 | 入口 | 状态 |
|---|---|---|---|
| T1 | CI-144 帧解析器（BIND-19 帧 + PFP 4 字节提取） | bytes + 零拷贝 | ⏳ |
| T2 | HTTP 代理中间件（axum layer，请求拦截 + PFP 决策） | axum + tower | ⏳ |
| T3 | 出网凭证注入集成（与 P3 物理边缘注入对接） | injection + CredentialStore | ⏳ |
| T4 | 性能压测（高并发决策延迟 + 审计写入吞吐量） | criterion + 压测脚本 | ⏳ |

### 1.2 核心承诺状态

| 承诺 | 状态 | 落地阶段 |
|---|---|---|
| 1 只读 4 字节，亚微秒级决策 | ✅ P1 验证（p99=322.89ps） | P1 |
| 2 fail-closed，永不放行未知 | ✅ P1 验证 + P2 HITL 超时自动 Reject | P1/P2 |
| 3 凭证永不在组件内存中 | ✅ P3 实现（identity_label + 物理边缘注入 + Zeroizing） | P3 |
| 4 每一次决策都不可篡改地记录 | ✅ P4 实现（SHA-256 链式日志 + WORM 存储 + 篡改检测） | P4 |

### 1.3 入口 ADR

- **ADR-0001**：Tuck Rust 重构 + 思想重新对齐（Active）
- **ADR-0002**：PFP 依赖策略 — 保留本地零拷贝实现（Active）
- **P5 新增 ADR 候选**：HTTP 代理架构选择、帧解析零拷贝策略、压测基准

### 1.4 验收标准

- T1：CI-144 帧解析器可正确提取 PFP 4 字节，零拷贝，支持 v1/v2 帧
- T2：HTTP 代理中间件可拦截请求、提取 PFP、执行 decide()、Pass/Reject
- T3：出网请求自动注入凭证（identity_label → 明文凭证 → 注入 → zeroize）
- T4：压测报告（p50/p99/p999 决策延迟 + 审计写入吞吐量 + 内存占用）
- `cargo test --workspace` 全绿 + 0 warning
- 端到端测试：HTTP 请求 → Tuck 拦截 → PFP 决策 → 凭证注入 → 出网

### 1.5 下一阶段预览：P6 — 生态联调

- 与 Anaphase 端到端联调（Anaphase 调用 Tentacle，Tuck 拦截凭证注入）
- 与 Tentacle 联调（Tentacle 工具执行经过 Tuck 安全闸门）
- 与 Cellrix 联调（Tuck 决策状态在 Cellrix 中展示）
- 与 CI-144 v2.0 PAL 对接（Tuck 消费 PAL 特征做硬实时决策）
- 完整生态演示：Helix-Mind 思考 → Anaphase 编排 → Tentacle 执行 → Tuck 安全 → Cellrix 展示

---

## 2. 阶段总览（地图，不展开）

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 方法论初始化 + Rust 项目骨架 | ✅ 已完成 |
| P1 | 核心骨架（PFP 读取 + 硬实时决策 + fail-closed + SAP 可选增强） | ✅ 已完成 |
| P2 | 策略引擎（策略配置 + HITL 执行闸 + CATASTROPHIC 硬覆盖 + 热加载） | ✅ 已完成 |
| P3 | 凭证物理注入（identity_label → 明文凭证 + zeroize + HSM/TPM） | ✅ 已完成 |
| P4 | 全息审计（SHA-256 链式日志 + WORM 存储 + 查询 API + 篡改检测） | ✅ 已完成 |
| **P5** | **传输层集成（CI-144 帧代理 + HTTP/gRPC 接入 + 凭证注入集成）** | **🚧 进行中** |
| P6 | 生态联调（与 Anaphase/Tentacle/Cellrix 端到端联调） | ⏳ 规划 |

---

## 3. 活跃决策与契约指针（不展开）

| 项 | 指针 |
|---|---|
| 核心承诺 | VISION.md 第四节（4 条承诺） |
| 特有铁律 | DNA.md 第五节（5 条：PFP 只读/fail-closed/凭证/审计/无分配） |
