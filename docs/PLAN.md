# Tuck 开发导航牌（PLAN）

> **版本**：v0.4.0（P3 凭证物理注入，2026-08-29）
> **状态**：🚧 P3 — 凭证物理注入（进行中）
> **上一阶段**：P2 — 策略引擎 ✅ 已完成（见 GROWTH.md，64 tests，策略/HITL/CATASTROPHIC/热加载）
> **分支**：rs
> **所属方法论**：phyt-DNA v1.0（PLAN 动态流转闭环，方法论锚点项目 https://github.com/Jasonmilk/phyt-DNA）
> **规则**：本文件只含当前阶段 + 下一阶段预览 + 阶段总览地图。完成阶段 → GROWTH.md。总行数 ≤150，超出触发历史迁移。

---

## 1. 当前阶段：P3 — 凭证物理注入

> **状态**：🚧 进行中。
> **前置依赖**：P2 策略引擎 ✅（64 tests，策略配置/HITL/CATASTROPHIC/热加载）。
> **目标**：identity_label → 明文凭证映射、物理边缘注入、注入后 zeroize、HSM/TPM 支持、凭证零化验证。

### 1.1 目标

| 任务 | 内容 | 入口 | 状态 |
|---|---|---|---|
| T1 | CredentialStore trait + identity_label 映射 | zeroize + serde | ⏳ |
| T2 | 物理边缘注入（出网前注入，注入后 zeroize） | zeroize + SecretString | ⏳ |
| T3 | FileCredentialStore 实现（开发环境） | 加密文件存储 | ⏳ |
| T4 | 凭证零化验证测试 + HSM/TPM trait 预留 | 内存审查测试 | ⏳ |

### 1.2 核心承诺状态

| 承诺 | 状态 | 落地阶段 |
|---|---|---|
| 1 只读 4 字节，亚微秒级决策 | ✅ P1 验证（p99=322.89ps） | P1 |
| 2 fail-closed，永不放行未知 | ✅ P1 验证（≥12 异常类别 100% Reject） | P1 |
| 3 凭证永不在组件内存中 | 🚧 P3 实现（identity_label 流转 + 物理边缘注入 + zeroize） | P3 |
| 4 每一次决策都不可篡改地记录 | 🚧 P2 部分（HITL/CATASTROPHIC/重载历史）→ P4 完整 | P2/P4 |

### 1.3 入口 ADR

- **ADR-0001**：Tuck Rust 重构 + 思想重新对齐（Active）
- **ADR-0002**：PFP 依赖策略 — 保留本地零拷贝实现（Active）
- **P3 新增 ADR 候选**：凭证存储格式选择、zeroize 实现策略、HSM/TPM 接口设计

### 1.4 验收标准

- T1：CredentialStore trait 定义完整（get/put/delete），identity_label 格式规范
- T2：凭证注入后 1ms 内 zeroize，内存中无明文凭证残留
- T3：FileCredentialStore 可加载/保存凭证，加密存储（AES-GCM 或系统 keychain）
- T4：零化验证测试通过，HSM/TPM trait 预留（不实现，仅定义接口）
- `cargo test --workspace` 全绿 + 0 warning
- 凭证注入不影响硬实时路径（decide() 仍 p99 <1μs）

### 1.5 下一阶段预览：P4 — 全息审计

- SHA-256 链式审计日志（每条包含上一条哈希）
- WORM 存储（追加写，不可修改/删除）
- 审计查询 API（按时间范围/Risk-Level/决策类型查询）
- 篡改检测（验证哈希链完整性）
- 审计日志与 HITL/CATASTROPHIC/策略重载历史整合

---

## 2. 阶段总览（地图，不展开）

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 方法论初始化 + Rust 项目骨架 | ✅ 已完成 |
| P1 | 核心骨架（PFP 读取 + 硬实时决策 + fail-closed + SAP 可选增强） | ✅ 已完成 |
| P2 | 策略引擎（策略配置 + HITL 执行闸 + CATASTROPHIC 硬覆盖 + 热加载） | ✅ 已完成 |
| **P3** | **凭证物理注入（identity_label → 明文凭证 + zeroize + HSM/TPM）** | **🚧 进行中** |
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
