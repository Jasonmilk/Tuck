# Tuck 开发导航牌（PLAN）

> **版本**：v0.7.0（P6 生态联调，2026-08-29）
> **状态**：🚧 P6 — 生态联调（规划中）
> **上一阶段**：P5 — 传输层集成 ✅ 已完成（见 GROWTH.md，212 tests，帧解析+HTTP拦截+凭证注入+性能压测）
> **分支**：rs
> **所属方法论**：phyt-DNA v1.0（PLAN 动态流转闭环，方法论锚点项目 https://github.com/Jasonmilk/phyt-DNA）
> **规则**：本文件只含当前阶段 + 下一阶段预览 + 阶段总览地图。完成阶段 → GROWTH.md。总行数 ≤150，超出触发历史迁移。

---

## 1. 当前阶段：P6 — 生态联调

> **状态**：⏳ 规划中。P5 已完成，等待用户确认进入 P6。
> **前置依赖**：P5 传输层集成 ✅（212 tests，帧解析+HTTP拦截+凭证注入+性能压测）。
> **目标**：与 Anaphase/Tentacle/Cellrix 端到端联调，验证 Tuck 在 Helix 生态中的完整角色。

### 1.1 目标

| 任务 | 内容 | 入口 | 状态 |
|---|---|---|---|
| T1 | 与 Anaphase 联调（Anaphase 调用 Tentacle，Tuck 拦截凭证注入） | 集成测试 | ⏳ |
| T2 | 与 Tentacle 联调（Tentacle 工具执行经过 Tuck 安全闸门） | 集成测试 | ⏳ |
| T3 | 与 Cellrix 联调（Tuck 决策状态在 Cellrix 中展示） | 状态流 | ⏳ |
| T4 | 与 CI-144 v2.0 PAL 对接（Tuck 消费 PAL 特征做硬实时决策） | 协议对接 | ⏳ |

### 1.2 核心承诺状态

| 承诺 | 状态 | 落地阶段 |
|---|---|---|
| 1 只读 4 字节，亚微秒级决策 | ✅ P1 验证（p99=322.89ps） | P1 |
| 2 fail-closed，永不放行未知 | ✅ P1 验证 + P2 HITL + P5 拦截器 | P1/P2/P5 |
| 3 凭证永不在组件内存中 | ✅ P3 实现 + P5 注入后 zeroize | P3/P5 |
| 4 每一次决策都不可篡改地记录 | ✅ P4 实现（SHA-256 链式日志 + WORM） | P4 |

### 1.3 入口 ADR

- **ADR-0001**：Tuck Rust 重构 + 思想重新对齐（Active）
- **ADR-0002**：PFP 依赖策略 — 保留本地零拷贝实现（Active）
- **P6 新增 ADR 候选**：生态联调架构、CI-144 v2.0 对接策略

### 1.4 验收标准

- T1：Anaphase → Tentacle 调用链中，Tuck 正确拦截并注入凭证
- T2：Tentacle 工具执行经过 Tuck 安全闸门，Reject 时工具不执行
- T3：Tuck 决策状态（Pass/Reject/HITL/CATASTROPHIC）在 Cellrix 中实时展示
- T4：Tuck 消费 CI-144 v2.0 PAL 特征（24 字节），向后兼容 v1.0
- 端到端演示：Helix-Mind 思考 → Anaphase 编排 → Tentacle 执行 → Tuck 安全 → Cellrix 展示

### 1.5 下一阶段预览：P7 — 生产就绪

- 配置文件完善（TOML 策略 + 环境变量 + 命令行参数）
- 日志系统（结构化日志 + 日志轮转 + 日志级别）
- 监控指标（Prometheus metrics + 健康检查端点）
- 部署文档（Docker + systemd + Kubernetes）
- 安全审计（第三方审计 + 渗透测试）

---

## 2. 阶段总览（地图，不展开）

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 方法论初始化 + Rust 项目骨架 | ✅ 已完成 |
| P1 | 核心骨架（PFP 读取 + 硬实时决策 + fail-closed + SAP 可选增强） | ✅ 已完成 |
| P2 | 策略引擎（策略配置 + HITL 执行闸 + CATASTROPHIC 硬覆盖 + 热加载） | ✅ 已完成 |
| P3 | 凭证物理注入（identity_label → 明文凭证 + zeroize + HSM/TPM） | ✅ 已完成 |
| P4 | 全息审计（SHA-256 链式日志 + WORM 存储 + 查询 API + 篡改检测） | ✅ 已完成 |
| P5 | 传输层集成（CI-144 帧解析 + HTTP 拦截 + 凭证注入 + 性能压测） | ✅ 已完成 |
| **P6** | **生态联调（与 Anaphase/Tentacle/Cellrix/CI-144 v2.0 端到端联调）** | **⏳ 规划中** |
| P7 | 生产就绪（配置/日志/监控/部署/安全审计） | ⏳ 规划 |

---

## 3. 活跃决策与契约指针（不展开）

| 项 | 指针 |
|---|---|
| 核心承诺 | VISION.md 第四节（4 条承诺） |
| 特有铁律 | DNA.md 第五节（5 条：PFP 只读/fail-closed/凭证/审计/无分配） |
