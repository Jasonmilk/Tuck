# Tuck 生长记录（GROWTH）

> **所属方法论**：phyt-DNA v1.0
> **规则**：保留最近 3 次健康快照。超过 3 条时，最旧的移入 `docs/archive/growth/`。历史永不删除。

---

### 2026-08-29 P5 传输层集成 ✅ 完成

- **事件**：P5 传输层集成 — CI-144 帧解析器 + HTTP 拦截器 + 出网凭证注入集成 + 性能压测
- **关键决策**：
  - 帧解析器零拷贝：Frame 持有原始缓冲区引用，无堆分配，PFP 提取是简单的 4 字节切片
  - HTTP 拦截器框架无关：操作通用 header map，不硬依赖 axum/actix，可轻松适配任何 Web 框架
  - 出网处理器组合模式：OutboundHandler 组合 HttpInterceptor + InjectionEngine，两者互不感知
  - 凭证注入按需驱动：仅当决策为 Allow/HardOverride 时才解析 identity_label 并注入凭证，Rejected 请求永不触碰凭证存储
  - 性能压测覆盖全链路：帧解析、HTTP 拦截、凭证注入、审计写入、完整流水线
- **代码实现**：
  - `frame.rs`：CI-144 帧解析器（FrameHeader + Frame + FrameBuilder，零拷贝，16 tests）
  - `proxy.rs`：HTTP 拦截器（HttpInterceptor + InterceptResult + base64 编解码，14 tests）
  - `outbound.rs`：出网处理器（OutboundHandler + OutboundResult + OutboundDecision，9 tests）
  - `benches/integration_benchmark.rs`：集成性能基准测试（5 组基准：帧解析/HTTP 拦截/凭证注入/审计吞吐量/完整流水线）
- **测试结果**：212 个测试全部通过（173 P0-P4 + 16 frame + 14 proxy + 9 outbound），0 failure
- **核心承诺**：
  - 承诺 1（亚微秒决策）：✅ P1 验证，P5 帧解析+拦截全链路仍亚微秒
  - 承诺 2（fail-closed）：✅ P1 验证 + P2 HITL + P5 拦截器缺失 PFP 直接拒绝
  - 承诺 3（凭证永不在组件内存中）：✅ P3 实现 + P5 注入后立即 zeroize
  - 承诺 4（每一次决策都不可篡改地记录）：✅ P4 实现
- **六大工程原则**：全部体现（极致解耦：帧/拦截/注入/审计独立模块 / 按需加载：PFP 提取是切片，无预计算 / 按需驱动：凭证注入仅在 Allow 时触发 / 极致复用：base64/SHA-256/serde 生态复用 / 物理事实优先：PFP 从请求头提取，Tuck 不发明 / 确定性优先：固定偏移帧结构 + 固定决策路径）
- **健康度**：212 tests + 18 模块 + 2 组基准测试
- **版本**：v0.6.0（P5 完成）

### 2026-09-05 P6-T5 Cellrix 状态流 ✅ 完成（P0-P7 全部完成）

- **事件**：P6-T5 Cellrix 状态流 + P6/P7 文档对齐（ADR-0003）
- **背景**：物理核验发现 P6-T1..T4 与 P7-T1..T4 已实现并推送（git `613051d`..`0b42e0a`），但 PLAN 停在 v0.7.0 P6 进行中、GROWTH 只记到 P5——P6-T5 是 P6 唯一代码缺口
- **关键决策**：
  - 状态流 = 拉模式查询接口（StatusProvider：summary + recent_decisions），不做推送/订阅——Tuck 零通知义务，展示层按需拉取
  - DecisionSummary 聚合 Metrics 原子计数（O(1) 实时）；DecisionEvent 投影 AuditLog 链（P4 复用，零新存储/写路径）
  - 事件投影裁剪 5 字段（timestamp/decision/risk/modality/source），不持完整 AuditEntry——按需加载，防数据膨胀
  - Metrics 只读 getter 按需添加（decision_counts/risk_counts），写入路径零改动
  - Cellrix 消费 = 跨仓库债（Tuck 交付接口面，消费在 Cellrix 仓库）
- **代码实现**：
  - `status.rs`：StatusProvider trait + AuditStatusProvider + DecisionSummary/DecisionEvent（6 tests）
  - `metrics.rs`：DecisionCounts/RiskCounts 只读结构 + 2 getter
  - `lib.rs`：pub mod status
- **测试结果**：316 个测试全部通过（310 基线 + 6 status），0 failure
- **核心承诺**：全部维持（决策亚微秒/fail-closed/凭证零内存/审计链不可篡改）
- **健康度**：316 tests + 21 模块 + P0-P7 全绿
- **版本**：v0.8.0（P0-P7 全部完成）

---

### 2026-09-05 P6-T1..T4 + P7 完成（补记，git 核验）

- **事件**：P6 生态联调（SAP 对接 + Mind/Anaphase/Tentacle 联调）与 P7 生产就绪（配置/日志/监控/部署）——补记健康快照（此前文档未记录）
- **关键决策**：
  - SAP 对接：PAH 签名验证 + LRU 防重放缓存 + decide_with_sap 可选增强（无 SAP 按 PFP 决策，非硬实时路径）
  - 规则 6：Replay-Enable=0 强制降级 MEDIUM + 强制签名验证
  - 联调接口：MindBridge / AnaphaseBridge（SecurityGate）/ TentacleBridge（PluginAuditor + ToolExecutionGate）——trait 隔离，跨仓库零耦合
  - P7：TOML 配置 + 环境变量覆盖 + 结构化日志 + Prometheus 指标 + Docker/systemd 部署
- **代码实现**：sap.rs（防重放缓存 + 签名验证 + decide_with_sap）、mind_bridge.rs / anaphase_bridge.rs / tentacle_bridge.rs、config.rs / logging / metrics.rs / health.rs / Dockerfile
- **提交**：`613051d`（P6-T1）`a087979`（T2）`0842a0b`（T3）`b379034`（T4）`0189549`/`3f7a279`/`1d2e10f`/`0b42e0a`（P7-T1..T4）

---

---
## 记录 5：test-utils feature 公开 InMemoryCredentialStore（2026-09-06）
**变异类型**：生态复用小改进（下游消费方复用测试存储）
**关键决策**：`InMemoryCredentialStore` 原为 `#[cfg(test)]`（Tuck 内部测试专用），下游 crate（Anaphase D'-2 闸门适配器测试）无法复用——改为 `#[cfg(any(test, feature = "test-utils"))]` + `[features] test-utils`（默认关闭，发布 API 面不变）；Tuck 自身测试（cfg(test)）不受影响
**验证**：316 测试全绿（纯可见性变化，零行为差异）；Anaphase tuck_gate 测试改复用 Tuck store（f6c2421）
**状态**：✅ 完成（0001dde）

*（后续生长记录在此追加，超过 3 条时最旧的移入 archive/growth/）*
