# 核心架构（architecture）

> **所属方法论**：phyt-DNA v1.0
> **性质**：Tuck 的核心架构法则。模块划分、依赖关系、硬实时路径。

---

## 架构原则

| # | 原则 | 说明 |
|---|---|---|
| 1 | **PFP 只读，不解密载荷** | 硬实时路径只读取 PFP 4 字节，不调用 intent 解析、载荷解密、SAP 验证 |
| 2 | **硬实时优先，功能后置** | `decide()` 函数（硬实时路径）优先优化，非实时功能（审计查询、配置管理）后置 |
| 3 | **策略与执行分离** | 安全策略（Risk-Level → Decision 映射）可配置，执行引擎（读取+决策）不可变 |
| 4 | **core 无网络依赖** | `tuck-core` crate 不依赖网络、不依赖传输层，可独立测试和复用 |

---

## 模块划分（workspace 多 crate）

| crate | 职责 | 依赖 | 状态 |
|---|---|---|---|
| `tuck-core` | 硬实时核心：PFP 读取、Decision 类型、`decide()` 函数、fail-closed 异常处理 | bind19 (PFP 类型) | 🚧 P0 |
| `tuck-policy` | 策略引擎：Risk-Level 策略配置、HITL 执行闸、CATASTROPHIC 硬覆盖 | tuck-core | ⏳ P2 |
| `tuck-credential` | 凭证物理注入：identity_label 映射、明文凭证注入、零化、HSM/TPM 支持 | tuck-core | ⏳ P3 |
| `tuck-audit` | 全息审计：SHA-256 链式日志、WORM 存储、查询 API、篡改检测 | tuck-core | ⏳ P4 |
| `tuck-proxy` | 传输层集成：CI-144 帧代理、HTTP 中间件、gRPC 接入 | tuck-core + tuck-policy + tuck-credential + tuck-audit | ⏳ P5 |
| `tuck` | 二进制入口：组装所有 crate，提供 CLI 和配置 | 所有 crate | ⏳ P5 |

---

## 硬实时路径（`decide()` 函数）

```
输入：&Frame（BIND-19 帧引用）
  │
  ▼
1. 读取 PFP（固定偏移 4 字节，零拷贝）
  │  pf p = frame.pfp();  // 直接引用，不复制
  │
  ▼
2. 位运算提取字段（无分支）
  │  risk = (pfp[2] >> 2) & 0b11;
  │  override_flag = (pfp[3] >> 1) & 0b1;
  │  output_dest = pfp[3] & 0b1;
  │
  ▼
3. match 决策（编译器优化为跳转表，无分支预测失败）
  │  match (risk, override_flag) {
  │    (LOW, _) => Pass,
  │    (MEDIUM, _) => Pass,
  │    (CRITICAL, _) => NeedHumanConfirm,
  │    (CATASTROPHIC, 1) => HardOverridePass,
  │    (CATASTROPHIC, 0) => Reject,
  │    _ => Reject,  // fail-closed
  │  }
  │
  ▼
输出：Decision（Pass/Reject/NeedHumanConfirm/HardOverridePass）
```

**硬实时约束**：
- 无堆分配（无 `Vec::new`、`String::new`、`Box::new`）
- 无锁（无 `Mutex`、`RwLock`）
- 无 await（异步操作在硬实时路径外）
- 无 panic（所有 `unwrap()` 替换为 `match` 或 `?`）
- p99 < 1μs

---

## 数据流

```
CI-144 帧（BIND-19 + PFP + SAP + INTENT-7 + 载荷）
    │
    ▼
tuck-core::decide()  ← 读取 PFP 4 字节，亚微秒级决策
    │
    ├─→ Decision::Pass ──────────────→ 帧继续流通（Anaphase/Tentacle）
    │
    ├─→ Decision::Reject ────────────→ 帧丢弃 + 审计日志 + ERROR 信号
    │
    ├─→ Decision::NeedHumanConfirm ──→ 暂停帧 + 人类确认请求（Cellrix/CLI）
    │                                     确认后 Pass，超时后 Reject
    │
    └─→ Decision::HardOverridePass ──→ 帧优先通过（CATASTROPHIC + Override-Flag）
                                          + 审计日志 + 紧急信号
    │
    ▼
tuck-audit::log()  ← 所有决策写入审计日志（SHA-256 链式，WORM）
```

---

## 扩展点

| 扩展点 | 扩展方式 | 约束 |
|---|---|---|
| 新的 Risk-Level 策略 | 配置文件修改 `tuck-policy` 策略映射 | 不修改 `decide()` 执行引擎 |
| 新的传输层 | 新增 `tuck-proxy` 适配器（HTTP/gRPC/STDIO） | 不修改 `tuck-core` |
| 新的凭证存储 | 实现 `CredentialStore` trait（HSM/TPM/Vault/文件） | 不修改 `tuck-core` |
| 新的审计存储 | 实现 `AuditStore` trait（WORM 文件/数据库/对象存储） | 不修改 `tuck-core` |

---

*《核心架构》v2.0 完。*
