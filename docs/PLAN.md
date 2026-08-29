# Tuck 开发导航牌（PLAN）

> **版本**：v0.7.0（P6 生态联调，2026-08-30）
> **状态**：🚧 P6 — 生态联调（进行中）
> **上一阶段**：P5 — 传输层集成 ✅ 已完成（见 GROWTH.md，212 tests，帧解析+HTTP拦截+凭证注入+性能压测）
> **分支**：rs
> **所属方法论**：phyt-DNA v1.0（PLAN 动态流转闭环，方法论锚点项目 https://github.com/Jasonmilk/phyt-DNA）
> **规则**：本文件只含当前阶段 + 下一阶段预览 + 阶段总览地图。完成阶段 → GROWTH.md。总行数 ≤150，超出触发历史迁移。

---

## 1. 当前阶段：P6 — 生态联调

> **状态**：🚧 进行中。P5 已完成，进入 P6-T1。
> **前置依赖**：P5 传输层集成 ✅（212 tests，帧解析+HTTP拦截+凭证注入+性能压测）。
> **目标**：自底向上完成 Helix 生态联调——协议层 → 灵魂层 → 编排层 → 执行层 → 展示层。

### 1.1 优先级与任务

| 优先级 | 任务 | 内容 | 入口 | 状态 |
|---|---|---|---|---|
| **P6-T1** | CI-144 协议家族对接 | PFP 4 字节已就绪，补全 SAP 防重放缓存 + 签名验证 + 规则6降级 | sap.rs | 🚧 |
| **P6-T2** | Helix-Mind 联调 | 安全决策反馈 + 审计日志消费 + 认知工艺安全约束 | 集成测试 | ⏳ |
| **P6-T3** | Anaphase 联调 | Anaphase 编排调用 Tentacle 时经过 Tuck 闸门 + 凭证注入 | 集成测试 | ⏳ |
| **P6-T4** | Tentacle 联调 | Tentacle 工具执行经过 Tuck 安全闸门，Reject 时工具不执行 | 集成测试 | ⏳ |
| **P6-T5** | Cellrix 联调 | Tuck 决策状态在 Cellrix 实时展示（Pass/Reject/HITL/CATASTROPHIC） | 状态流 | ⏳ |

**优先级理由**：协议层 → 灵魂层 → 编排层 → 执行层 → 展示层，自底向上，每一层稳定后再联调上一层。

### 1.2 P6-T1 详细范围（CI-144 协议家族对接）

> **注意**：CI-144 v2.0 已升级为协议家族方案，不是 24 字节 PAL。
> - **PFP-xCF14**（4 字节，冻结层）— Tuck 已实现，硬实时决策只读这 4 字节
> - **SAP-xCF14**（28 字节，演进层）— 防重放/签名验证，可选增强

| 子任务 | 内容 | 状态 |
|---|---|---|
| T1.1 | SAP 帧解析（28 字节：Seq-Counter + PAH-Hash + PAH-Signature + 版本） | ⏳ |
| T1.2 | Seq-Counter 防重放缓存（按 source_id 分片，LRU，≥1024 源） | ⏳ |
| T1.3 | PAH-Signature 验证（64-bit 截断，软件阶段 ed25519，spawn_blocking） | ⏳ |
| T1.4 | 规则 6：Replay-Enable=0 时强制降级到 MEDIUM + 强制签名验证 | ⏳ |
| T1.5 | SAP 可选集成：decide_with_sap() — 无 SAP 按 PFP 决策，有 SAP 增强验证 | ⏳ |
| T1.6 | 与 frame.rs 集成：Frame 解析时自动提取 SAP（如果 SAP-Present=1） | ⏳ |

### 1.3 核心承诺状态

| 承诺 | 状态 | 落地阶段 |
|---|---|---|
| 1 只读 4 字节，亚微秒级决策 | ✅ P1 验证（p99=322.89ps） | P1 |
| 2 fail-closed，永不放行未知 | ✅ P1 验证 + P2 HITL + P5 拦截器 | P1/P2/P5 |
| 3 凭证永不在组件内存中 | ✅ P3 实现 + P5 注入后 zeroize | P3/P5 |
| 4 每一次决策都不可篡改地记录 | ✅ P4 实现（SHA-256 链式日志 + WORM） | P4 |

### 1.4 入口 ADR

- **ADR-0001**：Tuck Rust 重构 + 思想重新对齐（Active）
- **ADR-0002**：PFP 依赖策略 — 保留本地零拷贝实现（Active）
- **P6 新增 ADR 候选**：SAP 防重放缓存策略、PAH 签名验证降级模式、Helix-Mind 安全反馈通道

### 1.5 验收标准

- T1：SAP 28 字节解析正确，防重放缓存命中/未命中正确，签名验证通过/失败正确，规则6降级正确
- T2：Helix-Mind 可接收 Tuck 安全决策反馈，可查询审计日志，认知工艺涉及物理动作时携带 PFP 风险标签
- T3：Anaphase → Tentacle 调用链中，Tuck 正确拦截并注入凭证
- T4：Tentacle 工具执行经过 Tuck 安全闸门，Reject 时工具不执行
- T5：Tuck 决策状态在 Cellrix 中实时展示
- 端到端演示：Helix-Mind 思考 → Anaphase 编排 → Tentacle 执行 → Tuck 安全 → Cellrix 展示

### 1.6 下一阶段预览：P7 — 生产就绪

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
| **P6** | **生态联调（协议家族+Helix-Mind+Anaphase+Tentacle+Cellrix，自底向上）** | **🚧 进行中** |
| P7 | 生产就绪（配置/日志/监控/部署/安全审计） | ⏳ 规划 |

---

## 3. 活跃决策与契约指针（不展开）

| 项 | 指针 |
|---|---|
| 核心承诺 | VISION.md 第四节（4 条承诺） |
| 特有铁律 | DNA.md 第五节（5 条：PFP 只读/fail-closed/凭证/审计/无分配） |
| CI-144 协议家族 | PFP-xCF14（4字节冻结）+ SAP-xCF14（28字节演进），非 24 字节 PAL |
