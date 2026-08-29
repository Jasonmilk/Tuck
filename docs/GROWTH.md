# Tuck 生长记录（GROWTH）

> **所属方法论**：phyt-DNA v1.0
> **规则**：保留最近 3 次健康快照。超过 3 条时，最旧的移入 `docs/archive/growth/`。历史永不删除。

---

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
