# Tuck 生长记录（GROWTH）

> **所属方法论**：phyt-DNA v1.0
> **规则**：保留最近 3 次健康快照。超过 3 条时，最旧的移入 `docs/archive/growth/`。历史永不删除。

---

### 2026-09-07 真实链路 live 验证 + 凭证治理机制 ✅（ADR-0004 D12 收口）

- **事件**：①Anaphase reasoning_endpoint 真实切到 Tuck 网关（tk-local-gate 身份凭证，
  真实 deepseek key 移入 Tuck config.toml，gitignored）——**live 验证达成**：真实 deepseek
  响应经 Tuck 之门返回，审计链记录 request/response 对（dest=external，hash 链），
  `/v1/audit` 查询可读。②**抓到一个 mock 掩盖的真伤**：workspace reqwest 为
  default-features=false + json/stream——**无 TLS 后端**，http（mock）通、https（真实 LLM）必挂；
  加 rustls-tls 后真实链路才通。③**API key 泄露审计**：发现真实 key 曾进 anaphase-helix
  git 历史（60df6f8 引入，已推送 GitHub）——唯一泄露面；机制修复：Anaphase config.toml/.bak
  untrack（部署配置永不进 git）、Tuck *.jsonl ignore；根治=用户轮换 key（待办）。
- **验证**：live curl——无 key 401 / 带 key 真实 deepseek 响应 / 审计链双记录 / 查询 2 条。
- **指标**：369 passed / 0 failed / 0 warnings（--all-features）。commit fc691d7（rustls）+ b4dc907/9335a7a（凭证治理）。
- **下一步**：用户轮换 deepseek key 后更新 Tuck/config.toml upstream_key；Cellrix 轨迹视图消费 /v1/audit。

### 2026-09-07 内容治理 v1.1 + 零警告专项 ✅（ADR-0004 + D11）

- **事件**：①零警告专项：tuck-core 47 个 warning 全清（Debug 补全 / 缺 doc / unused import / 类型极限比较），
  并修复 --all-features 下 AuditChain 非 Send 隐藏炸弹（signer 改 `Arc<dyn Fn + Send + Sync>`，
  SSE 治理流不再编译挂）。②会话令牌 JWT HS256（零魔法 hmac+sha2 手写，scope claim = CAPABILITY-13
  三模式 scopes 载体，透传进审计）。③只读审计查询 `GET /v1/audit`（trace_id/kind/action 过滤，
  身份门拦截，读链文件不碰热路径）——WebUI 驾驶舱轨迹视图数据源。④VISION v2.1 + SPEC/RNA 对齐：
  消除"不解密载荷 vs 内容治理"表面歧义——帧层（L1）永不碰载荷，内容层（L4）判字符串不判含义；
  DNA 红线未动。
- **关键决策**：双通道身份（静态 key 系统级 / JWT 会话级）；签发确定性（同 claims → 同 token）；
  审计查询直接读链文件（极致解耦，零热路径锁）。
- **指标**：368 passed / 0 failed / 0 warnings（--all-features）。commit 505566a（feat）+ a7d3fe8（零警告）+ 1ff6b60（文档）。
- **下一步**：Cellrix WebUI 驾驶舱轨迹视图按 trace_id join Tuck /v1/audit + Anaphase ledger（白盒可查落地）。

### 2026-09-07 旁路焊死装配 ✅（ADR-0004 D12）

- **事件**：Tuck 成为真实服务——`tuck` 二进制 feature `gateway`（按需加载），TuckConfig.gateway
  段装配 governance_router 并 serve（复用 server 端口，零硬编码）。L2 凭证物理注入落地：
  `upstream_key` 转发时替换 Authorization（调用方凭证永不离开本机，mock upstream 回显实证）。
  **Anaphase 零代码改动接入**：reasoning_endpoint 指向 Tuck 网关 = 物理上唯一出口（D7 铁律达成）。
- **验证**：e2e curl——无 key 401 / 带 key 200 / 上游只见 sk-upstream-secret / 审计链 e2e#1 双记录 /
  /v1/audit 查询 2 条 / 无 key 查询 401。
- **指标**：369 passed / 0 failed / 0 warnings（--all-features）。gateway 40（+1 L2 注入测试）。
- **下一步**：Cellrix 驾驶舱轨迹视图按 trace_id join Tuck /v1/audit + Anaphase ledger（白盒展示落地）。

### 2026-09-07 内容治理网关 v1 ✅ 完成（ADR-0004）

- **事件**：G-1..G-8 全部落地 — 审计链真实兑现 P4 承诺 + 网关内容治理全链路
- **关键决策**：
  - 审计链 = 唯一账本（无 Vault/WAL 第二账本），每笔调用 2 条记录（request/response）
  - Ed25519 批锚定防整链重写（min_anchors 下限）；密钥缺失降级纯哈希链（按需加载）
  - 三表 = 政策维度（mapping=pass+redact / guard=block+alert / hold=hold+alert），矩阵正交 fail-closed
  - 目的地分级：本地卫生（永不 block）/ 外网全拦；旁路焊死为架构铁律（D7）
  - 混淆态入链 + 映射表驻内存（Rosetta 规则）；demap_miss 不吞不拦打标
  - 判字符串不判含义（客观谓词检测，永不含义级审查）
  - 身份门 Bearer fail-closed（无密钥 = 拒绝一切）
  - 中文按字节熵误报修正：高熵检测限定连续 ASCII 段
  - SSE 流式 demap 滚动 carry（占位符跨 chunk 不损坏）；流结束写 response 审计
- **代码实现**：
  - `crates/tuck-audit/`：通用链（AuditRecord/Clock/verify_chain/verify_anchors，11 tests）
  - `crates/tuck-gateway/`：proxy（骨架）+ policy（检测引擎）+ matrix（政策矩阵）+ redact（映射表）+ gov（全链路接线，38 tests）
  - feature 门控按需加载：`audit`（tuck-audit 可选依赖）、`policy`、`redact`；gov gate 在 policy+redact
  - 链文件 0600；seq 从文件尾恢复（崩溃续写，确定性 id 不用 UUID）
- **测试结果**：365 个测试全部通过（316 core + 11 audit + 38 gateway），0 failure，0 warning
- **核心承诺**：承诺 4（不可篡改记录）从蓝图升级为真实兑现（SHA-256 链 + Ed25519 锚定 + 篡改/删行/重排/整链重写全检测）
- **六大工程原则**：全部体现（极致解耦：audit 是通用链、策略词汇不污染账本 / 按需加载：feature 门控 / 按需驱动：检测仅命中时 redact、密钥缺失降级 / 极致复用：axum/reqwest/ed25519-dalek / 物理事实优先：本地流量同样入账、token 流已发出不可拦 / 确定性优先：canonical JSON 定序哈希、会话级确定性占位符）
- **健康度**：365 tests + 6 crates（core/audit/gateway/cli）+ 3 feature 门控
- **版本**：v0.9.0（内容治理网关 v1）


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
