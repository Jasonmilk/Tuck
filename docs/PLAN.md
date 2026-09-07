# Tuck 开发导航牌（PLAN）

> **版本**：v0.9.0（内容治理网关 v1 完成，2026-09-07）
> **状态**：✅ 内容治理网关 v1（审计链 + 身份门 + 检测/混淆/拦截/全量审计）— 365 tests 全绿；旁路焊死待 Anaphase 联动
> **上一阶段**：G-1..G-4 — 内容治理网关（ADR-0004）✅ 本次完成
> **分支**：rs
> **所属方法论**：phyt-DNA v1.0（PLAN 动态流转闭环，方法论锚点项目 https://github.com/Jasonmilk/phyt-DNA）
> **规则**：本文件只含当前阶段 + 下一阶段预览 + 阶段总览地图。完成阶段 → GROWTH.md。总行数 ≤150，超出触发历史迁移。

---

## 1. 当前阶段：内容治理网关 v1（ADR-0004）✅ 完成

> **状态**：✅ G-1..G-4 全部落地，365 tests 全绿（316 + tuck-audit 11 + gateway 38）。
> **前置**：P0-P7 完成（rs 分支）；P4 全息审计此前为蓝图先行，本轮真实兑现。

### 1.1 内容治理网关交付（ADR-0004）

| 任务 | 内容 | 状态 |
|---|---|---|
| G-1 | tuck-audit 通用链（seq/ts/payload/prev_hash/hash + Clock 注入 + 崩溃续写 + 篡改检测） | ✅ commit 03fbc32 |
| G-2 | Ed25519 批锚定（Anchor 进链 + verify_anchors + min_anchors 防整链重写） | ✅ commit 03fbc32 |
| G-3 | 网关骨架（OpenAI 兼容代理 + SSE 流式透传 + auth 转发 + 502） | ✅ commit 20f22ab |
| G-4 | 检测引擎（dict/regex/entropy 三类规则，中文按字节熵误报已修） | ✅ commit d49e98c |
| G-5 | 政策矩阵（pass/block/hold × none/redact × alert，目的地分级，fail-closed） | ✅ commit 0adfc55 |
| G-6 | 映射表（会话级确定性占位符 + redact/demap + demap_miss 不吞不拦） | ✅ commit 2867e1d |
| G-7 | 全链路接线（检测→政策→redact→转发→JSON/SSE demap 滚动 carry） | ✅ commit 7eebb33 |
| G-8 | 身份门（Bearer fail-closed）+ 审计全量接入（request/response 双记录 + trace_id）+ 链文件 0600 | ✅ commit b9733b5 |

### 1.2 验收标准（G 全项）

- 本地外网全量过门：本地卫生（永不 block），外网全拦 ✅
- 每笔调用 2 条链记录（request/response），trace_id 跨账本关联 ✅
- 审计链只存混淆态，映射表驻内存绝不入链 ✅
- 无密钥 = 拒绝一切（fail-closed）✅
- 篡改/删行/重排/整链重写全部检测（哈希链 + 签名锚定）✅
- 测试：365 passed / 0 failed（tuck-audit 11 + gateway 38 + core 316）

### 1.1 P6 任务状态（以 git 与代码为准）

| 任务 | 内容 | 状态 |
|---|---|---|
| P6-T1 | CI-144 协议家族对接：PAH 签名验证 + LRU 防重放缓存 + decide_with_sap + 规则6降级 | ✅ commit 613051d |
| P6-T2 | Helix-Mind 联调：SecurityEvent 反馈 + AuditQuery + PFP 构造指南 + MindBridge | ✅ commit a087979 |
| P6-T3 | Anaphase 联调：SecurityGateRequest/Response + TuckSecurityGate + AnaphaseBridge | ✅ commit 0842a0b |
| P6-T4 | Tentacle 联调：PluginAuditRequest/Response + TuckPluginAuditor + ToolExecutionGate | ✅ commit b379034 |
| P6-T5 | **Cellrix 状态流：StatusProvider（summary + recent_decisions）** | ✅ 本次 ADR-0003 |

### 1.2 P6-T5 详细范围（本次交付）

- **status.rs**（tuck-core 内新模块，勿增 crate）：`StatusProvider` trait + `AuditStatusProvider` 实现
- **DecisionSummary**：运行期累计快照（决策计数 + 风险计数 + 最近决策）——从 `Metrics` 原子计数聚合（O(1)）
- **DecisionEvent**：单条决策投影（timestamp/decision/risk_level/modality/source）——从 `AuditLog` 链倒序投影（P4 复用，零新存储）
- **metrics.rs**：`DecisionCounts` / `RiskCounts` 只读结构 + `decision_counts()` / `risk_counts()` getter（写入路径零改动）
- **拉模式**：Cellrix 按需查询，Tuck 零推送开销；Cellrix 侧消费 = 跨仓库债（ADR-0003 D5）

### 1.3 验收标准（P6 全项）

- T1：SAP 解析/防重放/签名验证/规则6 正确 ✅
- T2：Mind 可接收安全决策反馈 + 查询审计 ✅
- T3：Anaphase 调用链中 Tuck 拦截 + 凭证注入 ✅
- T4：Tentacle 工具经闸门，Reject 不执行 ✅
- T5：决策状态可查询（summary/recent，316 测试覆盖）✅
- 测试：316 passed / 0 failed（+6 status 测试）

### 1.3 核心承诺状态

| 承诺 | 状态 | 落地阶段 |
|---|---|---|
| 1 只读 4 字节，亚微秒级决策 | ✅ p99=322.89ps | P1 |
| 2 fail-closed，永不放行未知 | ✅ P1+P2+P5 | P1/P2/P5 |
| 3 凭证永不在组件内存中 | ✅ P3+P5（zeroize） | P3/P5 |
| 4 每一次决策都不可篡改地记录 | ✅ P4 真实兑现（tuck-audit SHA-256 链 + Ed25519 锚定） | G-1/G-2 |

### 1.4 入口 ADR

- **ADR-0001**：Rust 重构 + 思想重新对齐（Active）
- **ADR-0002**：PFP 依赖策略 — 本地零拷贝实现（Active）
- **ADR-0003**：Cellrix 状态流 — StatusProvider 拉模式查询 + 审计投影（Active）
- **ADR-0004**：内容治理网关 — Tuck 差异化本体（Active，本次）

---

## 2. 下一阶段预览：生态消费联动（跨仓库）

Tuck 接口面已全部就绪，下一阶段是**生态消费**（非 Tuck 仓库内工程）：

- **Cellrix 渲染**：按 `StatusProvider` 消费决策状态（Pass/Reject/HITL/CATASTROPHIC 实时展示）— Cellrix 仓库
- **Anaphase D'-2**：`TuckSecurityGate`（P6-T3 已提供）接入 Anaphase pipeline — Anaphase 仓库
- **Mind P10a**：SecurityEvent 反馈消费 + 认知工艺安全约束 — Mind 仓库
- 联调演示：Mind 思考 → Anaphase 编排 → Tentacle 执行 → Tuck 安全 → Cellrix 展示

---

## 3. 阶段总览（地图，不展开）

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 方法论初始化 + Rust 项目骨架 | ✅ 已完成 |
| P1 | 核心骨架（PFP 读取 + 硬实时决策 + fail-closed + SAP 可选增强） | ✅ 已完成 |
| P2 | 策略引擎（策略配置 + HITL 执行闸 + CATASTROPHIC 硬覆盖 + 热加载） | ✅ 已完成 |
| P3 | 凭证物理注入（identity_label → 明文凭证 + zeroize + HSM/TPM） | ✅ 已完成 |
| P4 | 全息审计（SHA-256 链式日志 + WORM 存储 + 查询 API + 篡改检测） | ✅ 已完成（G-1/G-2 真实兑现） |
| P5 | 传输层集成（CI-144 帧解析 + HTTP 拦截 + 凭证注入 + 性能压测） | ✅ 已完成 |
| P6 | 生态联调（SAP 对接 + Mind/Anaphase/Tentacle/Cellrix 接口） | ✅ 已完成 |
| P7 | 生产就绪（配置/日志/监控/部署） | ✅ 已完成 |
| G-1..G-8 | 内容治理网关 v1（审计链 + 身份门 + 检测/混淆/拦截/全量审计） | ✅ 已完成（ADR-0004） |
| 消费期 | 生态消费联动（旁路焊死 / Cellrix 渲染 / Anaphase D'-2 / Mind P10a） | ⏳ 跨仓库待联动 |

---

## 4. 活跃决策与契约指针（不展开）

| 项 | 指针 |
|---|---|
| 核心承诺 | VISION.md 第四节（4 条承诺） |
| 特有铁律 | DNA.md 第五节（5 条：PFP 只读/fail-closed/凭证/审计/无分配） |
| CI-144 协议家族 | PFP-xCF14（4字节冻结）+ SAP-xCF14（28字节演进），非 24 字节 PAL |
| 状态流接口 | status.rs：StatusProvider（summary + recent_decisions） |
| 内容治理 | ADR-0004：全量过门 + 三表政策 + 判字符串不判含义 + 混淆态入链 |
