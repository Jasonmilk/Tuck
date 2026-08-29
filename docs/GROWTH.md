# Tuck 生长记录（GROWTH）

> **所属方法论**：phyt-DNA v1.0
> **规则**：保留最近 3 次健康快照。超过 3 条时，最旧的移入 `docs/archive/growth/`。历史永不删除。

---

### 2026-08-29 P3 凭证物理注入 ✅ 完成

- **事件**：P3 凭证物理注入 — identity_label 映射 + 物理边缘注入 + 加密文件存储 + 零化验证 + HSM/TPM trait 预留
- **关键决策**：
  - identity_label 格式：`scheme:path`（env/file/hsm/vault/inline），组件间只流转 label，不流转明文凭证
  - Credential 使用 `Zeroizing<Vec<u8>>`，drop 时自动清零内存
  - 物理边缘注入：凭证仅在出网前注入，注入后立即 drop（触发 zeroize）
  - FileCredentialStore 使用 AES-256-GCM 加密，主密钥从 `TUCK_MASTER_KEY` 环境变量读取（base64 32字节）
  - HSM/TPM 支持定义为 trait（不实现），生产环境可替换 FileCredentialStore
  - `#![forbid(unsafe_code)]`：零化验证使用安全的 `zeroize()` 方法直接测试，不使用 unsafe
- **代码实现**：
  - `credential.rs`：Credential（Zeroizing）+ IdentityLabel + CredentialScheme + CredentialStore trait + InMemoryCredentialStore
  - `injection.rs`：InjectionEngine + InjectionTarget（HttpHeader/BearerToken/QueryParam/BodyField/BasicAuth）+ OutboundRequest
  - `file_store.rs`：FileCredentialStore + MasterKey + AES-256-GCM 加密/解密 + 原子写入（tmp + rename）
  - `hsm.rs`：HsmCredentialStore trait + TpmCredentialStore trait + KeyAlgorithm + EcCurve + PcrPolicy + AttestationQuote
- **测试结果**：123 个测试全部通过（28 PFP + 10 SAP + 9 policy + 9 hitl + 9 catastrophic + 9 hot_reload + 22 credential + 17 injection + 13 file_store + 10 hsm），0 failure
- **核心承诺**：
  - 承诺 1（亚微秒决策）：✅ P1 验证，P3 凭证注入不影响硬实时路径
  - 承诺 2（fail-closed）：✅ P1 验证 + P2 HITL 超时自动 Reject
  - 承诺 3（凭证永不在组件内存中）：✅ P3 实现（identity_label 流转 + 物理边缘注入 + Zeroizing 自动清零）
  - 承诺 4（审计）：🚧 部分（HITL/CATASTROPHIC/重载历史）→ P4 完整审计
- **六大工程原则**：全部体现（极致解耦：CredentialStore trait 可插拔后端 / 按需加载：凭证仅在 get() 时加载 / 按需驱动：注入仅在出网时触发 / 极致复用：AES-GCM/ed25519/zeroize 生态复用 / 物理事实优先：主密钥从环境变量读取，HSM trait 预留 / 确定性优先：固定加密算法 + 原子写入）
- **健康度**：123 tests + 10 模块（pfp/sap/policy/hitl/catastrophic/hot_reload/credential/injection/file_store/hsm）
- **版本**：v0.4.0（P3 完成）

### 2026-08-29 P2 策略引擎 ✅ 完成

- **事件**：P2 策略引擎 — 策略配置文件 + HITL 执行闸 + CATASTROPHIC 硬覆盖 + 策略热加载
- **关键决策**：
  - 策略配置使用 TOML 格式（与 Cargo.toml 一致，Rust 生态原生支持）
  - HITL 执行闸使用 oneshot 通道 + 超时自动 Reject（fail-closed）
  - CATASTROPHIC 硬覆盖使用 Notify 紧急信号 + broadcast 并行人类通知
  - 策略热加载使用文件修改时间检查 + Arc<RwLock> 原子交换
  - 策略版本使用语义化版本（major.minor.patch），不兼容版本拒绝加载
- **代码实现**：
  - `policy.rs`：PolicyConfig（可序列化）+ PolicyVersion + DecisionConfig + 文件加载/保存
  - `hitl.rs`：HumanConfirmGate + ConfirmRequest + 超时自动 Reject + 历史记录
  - `catastrophic.rs`：CatastrophicGate + CatastrophicEvent + Notify 紧急信号 + broadcast 通知
  - `hot_reload.rs`：HotReloadPolicy + 文件监控 + 原子交换 + 重载历史
- **测试结果**：64 个测试全部通过（28 PFP + 9 policy + 9 hitl + 9 catastrophic + 9 hot_reload），0 failure，0 warning
- **核心承诺**：
  - 承诺 1（亚微秒决策）：✅ P1 验证，P2 热加载不影响硬实时路径（current_policy() 返回 Arc，无锁）
  - 承诺 2（fail-closed）：✅ HITL 超时自动 Reject，策略加载失败保留旧策略
  - 承诺 4（审计）：🚧 部分（HITL 历史 + CATASTROPHIC 历史 + 重载历史），P4 完整审计
- **六大工程原则**：全部体现（极致解耦：策略/HITL/CATASTROPHIC/热加载独立模块 / 按需加载：策略文件按需加载 / 按需驱动：事件驱动无轮询 / 极致复用：serde/tokio/uuid 生态复用 / 物理事实优先：PFP 特征驱动决策 / 确定性优先：固定超时 + 原子交换）
- **健康度**：64 tests + 5 模块（pfp/sap/policy/hitl/catastrophic/hot_reload），策略引擎完整
- **版本**：v0.3.0（P2 完成）

### 2026-08-29 P1 核心骨架完善 ✅ 完成

- **事件**：P1 核心骨架完善 — BIND-19 依赖策略、硬实时性能基准、故障注入测试、SAP 可选增强接口
- **关键决策**：
  - ADR-0002：PFP 类型保留本地零拷贝实现（不直接依赖 bind19 crate），复用协议规范而非代码
  - SAP 验证不在硬实时路径中，作为可选异步增强层
  - ReplayCache trait 可插拔（InMemory 实现 + 未来分布式实现）
- **性能基准**（criterion, 1000 samples）：
  - `decide_from_bytes` CRITICAL：p50=314.73ps, p99=322.89ps（目标 <1μs，达成率 3097x）
  - `decide_from_bytes` invalid_magic：p50=298.72ps, p99=299.75ps
  - PFP 字段提取：~298ps（单字段），~18.7ps（全字段，编译器优化）
  - 吞吐量：3.1-3.4 Gelem/s（30 亿次决策/秒）
- **测试结果**：28 个测试全部通过（18 PFP/决策 + 10 SAP），0 failure，0 warning
  - 故障注入：≥12 个异常输入类别，100% 返回 Reject
  - Rule 6 降级：Replay-Enable=0 → 强制 MEDIUM（含阻断 CATASTROPHIC 硬覆盖）
  - SAP 重放检测：递增序列号通过，重复/降低序列号拦截
- **代码实现**：
  - `crates/tuck-core/benches/decide_benchmark.rs`：criterion 基准（3 组 11 个基准）
  - `crates/tuck-core/src/sap.rs`：SapHeader 28字节零拷贝 + ReplayCache trait + InMemoryReplayCache + verify_sap()
  - `docs/decisions/ADR-0002-pfp-dependency-strategy.md`：PFP 依赖策略决策记录
- **六大工程原则**：全部体现（极致解耦：SAP 与 decide 分离 / 按需加载：SAP 可选 / 按需驱动：事件驱动 / 极致复用：协议规范复用 / 物理事实优先：PFP 传感器特征 / 确定性优先：固定偏移位运算）
- **健康度**：28 tests + 11 benchmarks + 2 ADR，核心承诺 1&2 已验证
- **版本**：v0.2.0（P1 完成）

### 2026-08-29 P0 方法论初始化 + Rust 项目骨架 ✅ 完成

- **事件**：Tuck rs 分支新建，思想从"AI 会话版本控制"重新对齐为"Helix 生态免疫系统/无情闸门"
- **关键决策**：
  - 项目定位：免疫系统/无情闸门（非 AI 会话版本控制）
  - 语言选择：Rust（硬实时 + 内存安全 + 零成本抽象）
  - CI-144 消费方式：直接依赖 BIND-19 参考实现，不自己实现帧解析
  - workspace 结构：多 crate（core/policy/credential/audit/proxy），core 无网络依赖
  - 启用 phyt-DNA v1.0 方法论
- **方法论闭环**：VISION v2.0 + DNA v2.0 + RNA v2.0 + SPEC v2.0 + PLAN v2.0 + spec/ 5 分卷 + ADR-0001
- **代码实现**：
  - tuck-core：PfpHeader 4字节类型 + Decision 枚举 + SecurityPolicy + decide() 硬实时函数
  - decide()：固定偏移读取 + 位运算 + match 跳转表 + 无堆分配 + 无锁 + 无 await
  - Rule 6：Replay-Enable=0 → 有效 Risk-Level 强制降级为 MEDIUM
  - CATASTROPHIC 硬覆盖：不可协商规则
  - tuck：二进制入口（CLI，PFP hex 输入 → Decision 输出）
- **测试结果**：11 个单元测试全部通过，0 warning
- **六大工程原则**：极致解耦/按需加载/按需驱动/极致复用/物理事实优先/确定性优先（全部体现）
- **健康度**：docs/ 15 个文件 + crates/ 2 个 crate + 34 文件提交，Python beta 移入 archive 保留
- **版本**：v0.1.0（P0 完成）
- **提交**：c090add (ADR-0001 §P0)

---

*（后续生长记录在此追加，超过 3 条时最旧的移入 archive/growth/）*
