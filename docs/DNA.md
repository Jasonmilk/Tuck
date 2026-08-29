# Tuck DNA — 不可变原则与自生长流程

> **版本**：v2.0（Rust 重构版）
> **日期**：2026-08-29
> **所属方法论**：phyt-DNA v1.0（方法论锚点项目 https://github.com/Jasonmilk/phyt-DNA）
> **继承自**：Tuck VISION.md v2.0（哲学内容源）、CI-144 PFP-xCF14 规范（消费方）
> **性质**：Tuck 的不可变原则与如何生长。修改 DNA 等于修改身份，旧身份的信用不会转移。

---

## 一、不可变原则（公理）

见 `docs/VISION.md` 原子原则表（8 条）。本文件不再重复原则内容，而是定义**工程映射**与**防腐化铁律**。

**工程映射（关键 4 条，对应核心承诺）**：

| 原则 | 工程映射 | 验收标准 |
|---|---|---|
| 1 只读 PFP，不解密载荷 | `tuck-core` 硬实时路径只调用 `bind19::pfp::PfpHeader`，不调用 `bind19::intent` 或载荷解密 | 代码审查：硬实时路径中无 intent/载荷引用 |
| 2 fail-closed，异常即拦截 | 所有 `Result::Err` 路径默认返回 `Decision::Reject`，无 `unwrap()` 或默认放行 | 故障注入测试：100% 异常场景拦截 |
| 3 零信任凭证：标签流转 | `tuck-core` 用 `identity_label: String` 替代明文 credentials；`tuck-proxy` 出网前物理注入 | 内存 grep 不出明文 Cookie/Token/API Key |
| 4 白盒可审计 | 所有决策写入 `audit_log`，SHA-256 链式，每条包含上一条哈希 | 审计日志验证：任意条目篡改可被检测 |

---

## 二、分层自纠偏系统（N/D/A）

| 层级 | 名称 | 形式 | 作用 |
|---|---|---|---|
| **N 层** | 叙事层（愿景） | `VISION.md` + `docs/SPEC.md` + `docs/spec/` | 顶层叙事，所有决策最终裁判 |
| **D 层** | 决策层（ADR） | `docs/decisions/ADR-*.md` | 记录架构决策的"为什么"与"放弃了什么" |
| **A 层** | 架构层（代码） | `crates/*/src/` 或 `src/` | 物理实现最终形态 |

---

## 三、文档生态 SOP

| 文档 | 职责 | 规则 |
|---|---|---|
| **PLAN.md** | 当前阶段导航 + 下一阶段预览 + 阶段总览 | ≤150 行，超出触发历史迁移 |
| **GROWTH.md** | 已完成阶段生长记录 | ≤3 条，超则归档至 `docs/archive/growth/` |
| **ADR** | 决策记录 | 两态（Draft/Active），Active 后不可覆写，仅可 Superseded |
| **归档** | 历史记录 | 随仓库版本化，永不删除 |

---

## 四、防腐化铁律（5 条，通用）

| # | 铁律 | 说明 |
|---|---|---|
| 1 | **版本以 spec/代码为源真相** | README/门面标注必须对齐，防版本漂移 |
| 2 | **契约冻结不可静默修改** | PFP 字段偏移/枚举值冻结，扩展走 Append-Only / reserved 预留 |
| 3 | **变更先 ADR（D 层冻结）→ 改代码 → 同步门面** | 决策先于代码 |
| 4 | **生长记录保留近 3 条，超则归档** | 历史永不删除，按需加载 |
| 5 | **提交前必须人工确认** | 无自动提交 |

---

## 五、Tuck 特有铁律（项目特有，AI 协作铁律第 9 条具体化）

| # | 特有铁律 | 说明 | 验收 |
|---|---|---|---|
| 1 | **PFP 只读红线** | 硬实时路径（`decide()` 函数）只读取 PFP 4 字节，不调用 intent 解析、载荷解密、SAP 验证（SAP 验证是可选增强，不在硬实时路径） | 代码审查：`decide()` 函数体中无 intent/payload/sap 引用 |
| 2 | **fail-closed 红线** | 任何 `Err`、`None`、超时、panic 都必须转化为 `Decision::Reject`，严禁 `unwrap_or(Decision::Pass)` 或默认放行 | 故障注入：100% 异常路径返回 Reject |
| 3 | **凭证红线** | Tuck 内存中只在物理注入的瞬间持有明文凭证，注入后立即零化（zeroize）。identity_label 可长期持有，明文凭证不可 | 内存审查：注入后 1ms 内明文凭证被零化 |
| 4 | **审计不可篡改红线** | 审计日志使用 SHA-256 链式（每条包含上一条哈希），WORM（Write Once Read Many）存储。严禁修改已写入的审计条目 | 篡改检测：任意条目修改后哈希链断裂 |
| 5 | **硬实时路径无分配红线** | `decide()` 函数不做堆分配（无 `Vec::new`、`String::new`、`Box::new`），不锁，不 await。使用栈上固定大小数组 | 性能测试：`decide()` p99 < 1μs，无堆分配 |

---

## 六、与生态的关系

- **对齐链**：Tuck 消费 PFP-xCF14（CI-144 冻结层）→ CI-144 是 Helix 生态血液 → Helix-Mind 是认知真相源
- **Tuck 是 CI-144 的第一个 PFP 消费者**：它的实现验证了 PFP 4 字节设计的实用性（亚微秒级决策、无需解密载荷）
- **独立通用 + Helix 原生优先**：Tuck 可独立用于任何 CI-144 兼容系统，Helix 生态是第一公民
- **rs 分支**为当前 Rust 重构，`archive/python-beta/` 保留早期 Python 实现为历史参考（哲学不成熟，仅供考古）

---

## 七、一句话总结

> **Tuck DNA 是免疫系统的基因锁：只读 PFP 4 字节 + fail-closed + 零信任凭证标签流转 + 全息审计。特有铁律（PFP 只读/fail-closed/凭证/审计/无分配）是硬实时路径的硬性约束，不改变其独立于全 AI Agent 社区的定位。**

---

*《Tuck DNA.md》v2.0 完。*
