# Tuck 开发导航牌（PLAN）

> **版本**：v2.0（P0 方法论初始化 + Rust 骨架，2026-08-29）
> **状态**：🚧 P0 — 方法论初始化 + Rust 项目骨架（进行中）
> **上一阶段**：无（rs 分支新建，Python beta 保留为 archive 参考）
> **分支**：rs
> **所属方法论**：phyt-DNA v1.0（PLAN 动态流转闭环，方法论锚点项目 https://github.com/Jasonmilk/phyt-DNA）
> **规则**：本文件只含当前阶段 + 下一阶段预览 + 阶段总览地图。完成阶段 → GROWTH.md。总行数 ≤150，超出触发历史迁移。

---

## 1. 当前阶段：P0 — 方法论初始化 + Rust 项目骨架

> **状态**：🚧 进行中（方法论文档已完成，Rust 骨架待初始化）。
> **前置依赖**：phyt-DNA v1.0 方法论锚点已建立 ✅；CI-144 v2.0-rc.1 参考实现已完成 ✅。

### 1.1 目标

| 任务 | 内容 | 入口 | 状态 |
|---|---|---|---|
| T1 | phyt-DNA 方法论初始化（VISION/DNA/RNA/SPEC/PLAN/GROWTH/DEPRECATE + spec/ + decisions/ + archive/） | phyt-DNA v1.0 模板 | ✅ 已完成 |
| T2 | Rust 项目骨架初始化（Cargo.toml + workspace + src/lib.rs + CI） | Rust 2021 edition | 🚧 进行中 |
| T3 | CI-144 依赖接入（bind19 crate 依赖 + PFP 类型导入） | BIND-19 v2.0-rc.1 | ⏳ |
| T4 | 基础类型定义（Decision 枚举 + TuckError + 配置结构） | VISION 核心承诺 | ⏳ |

### 1.2 代码真相源

- **T1 方法论**：docs/ 目录已初始化（15 个文件），VISION v2.0 思想重新对齐为免疫系统/无情闸门
- **T2 Rust 骨架**：待初始化。workspace 结构：`crates/tuck-core`（硬实时核心）、`crates/tuck-audit`（审计日志）、`crates/tuck-credential`（凭证注入）、`crates/tuck-proxy`（传输层代理）
- **T3 CI-144 依赖**：BIND-19 仓库已有 Rust 参考实现（v2.0-rc.1），可直接作为 git dependency 或发布 crates.io 后依赖
- **T4 基础类型**：Decision 枚举（Pass/Reject/NeedHumanConfirm/HardOverridePass），TuckError（PfpParseError/PolicyError/AuditError/CredentialError）

### 1.3 核心承诺状态（P0 阶段不验收，P1 起逐步兑现）

| 承诺 | 状态 | 落地阶段 |
|---|---|---|
| 1 只读 4 字节，亚微秒级决策 | ⏳ | P1（核心骨架） |
| 2 fail-closed，永不放行未知 | ⏳ | P1（核心骨架） |
| 3 凭证永不在组件内存中 | ⏳ | P3（凭证注入） |
| 4 每一次决策都不可篡改地记录 | ⏳ | P4（全息审计） |

### 1.4 入口 ADR

- **ADR-0001**：Tuck Rust 重构 + 思想重新对齐 + 免疫系统定位（Active，覆盖 P0-P6 技术选型大方向）
- **P0 新增 ADR 候选**：workspace 结构设计、CI-144 依赖方式（git dependency vs crates.io）、Decision 枚举定义（如与现有设计有重大偏离，需新建 ADR-0002）

### 1.5 已确认决策点（P0 D1-D4）

| # | 决策点 | 决议 | 状态 |
|---|---|---|---|
| D1 | 项目定位 | 免疫系统/无情闸门（非 AI 会话版本控制），思想重新对齐 | ✅ |
| D2 | 语言选择 | Rust（硬实时 + 内存安全 + 零成本抽象） | ✅ |
| D3 | CI-144 消费方式 | 直接依赖 BIND-19 Rust 参考实现，不自己实现帧解析 | ✅ |
| D4 | workspace 结构 | 多 crate（core/audit/credential/proxy），core 无网络依赖 | ✅ |

### 1.6 P0 进度

| 任务 | 内容 | 状态 | 测试 |
|---|---|---|---|
| T1 | 方法论初始化 | ✅ 已完成 | - |
| T2 | Rust 项目骨架 | 🚧 进行中 | - |
| T3 | CI-144 依赖接入 | ⏳ 待启动 | - |
| T4 | 基础类型定义 | ⏳ 待启动 | - |

### 1.7 验收标准

- T1：docs/ 15 个文件初始化完成，VISION/DNA/RNA/PLAN 内容与 Tuck 定位对齐
- T2：`cargo build --workspace` 成功，0 warning
- T3：`cargo tree` 显示 bind19 依赖，`use bind19::pfp::PfpHeader` 可编译
- T4：Decision/TuckError/Config 类型定义完整，单元测试通过
- `cargo test --workspace` 全绿 + 0 warning

### 1.8 下一阶段预览：P1 — 核心骨架（PFP 读取 + 硬实时决策路径）

- PFP 4 字节固定偏移读取（`bind19::pfp::PfpHeader`）
- `decide()` 函数实现（位运算 + match，无分支，无堆分配，无锁，无 await）
- Decision 枚举完整实现（Pass/Reject/NeedHumanConfirm/HardOverridePass）
- fail-closed 异常路径（所有 Err/None/超时 → Reject）
- 硬实时性能基准（p99 < 1μs，无堆分配）
- 故障注入测试（100% 异常场景拦截）

---

## 2. 阶段总览（地图，不展开）

| 阶段 | 内容 | 状态 |
|---|---|---|
| **P0** | **方法论初始化 + Rust 项目骨架** | **🚧 进行中** |
| P1 | 核心骨架（PFP 读取 + 硬实时决策路径 + fail-closed） | ⏳ 预览 |
| P2 | 策略引擎（Risk-Level 策略配置 + HITL 执行闸 + CATASTROPHIC 硬覆盖） | ⏳ 规划 |
| P3 | 凭证物理注入（identity_label → 明文凭证 + 零化 + HSM/TPM 支持） | ⏳ 规划 |
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
