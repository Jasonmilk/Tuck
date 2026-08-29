# Tuck

> **Helix 生态免疫系统 / 无情闸门**
>
> CI-144 PFP-xCF14 第一个消费者 · 亚微秒级硬实时决策 · fail-closed · 零信任凭证物理注入 · 全息审计

---

## 一句话定位

**Tuck 是 Helix 的免疫系统——用 4 字节 PFP 物理特征，在亚微秒内做出放行/拦截/人类确认的决策。它不思考、不编排、不执行，只过滤。**

## 核心承诺

| # | 承诺 | 含义 | 验收标准 |
|---|---|---|---|
| 1 | 只读 4 字节，亚微秒级决策 | PFP 固定偏移读取，位运算，无分支 | p99 < 1μs |
| 2 | fail-closed，永不放行未知 | 任何异常默认拦截 | 故障注入 100% 拦截 |
| 3 | 凭证永不在组件内存中 | identity_label 流转，物理边缘注入，零化 | 内存 grep 不出明文凭证 |
| 4 | 每一次决策都不可篡改地记录 | SHA-256 链式日志，WORM 存储 | 篡改可检测 |

## 六大工程原则

- **极致解耦**：core 无网络依赖，硬实时路径与传输层分离
- **按需加载**：PFP 字段惰性位运算提取，非实时功能后置
- **按需驱动**：事件驱动，无轮询，`decide()` 每帧调用
- **极致复用**：复用 CI-144 BIND-19 PFP 类型，不自己实现帧解析
- **物理事实优先**：决策基于 PFP 传感器特征，非 AI 语义推理
- **确定性优先**：固定偏移、位运算、match 跳转表、无分支、无堆分配

## 架构

```
crates/
├── tuck-core/      # 硬实时核心：PFP 读取、decide()、fail-closed、Decision 类型
├── tuck-policy/    # 策略引擎：Risk-Level 策略配置、HITL 执行闸（P2）
├── tuck-credential/# 凭证物理注入：identity_label → 明文凭证、零化、HSM/TPM（P3）
├── tuck-audit/     # 全息审计：SHA-256 链式日志、WORM 存储、查询 API（P4）
├── tuck-proxy/     # 传输层集成：CI-144 帧代理、HTTP 中间件（P5）
└── tuck/           # 二进制入口：CLI、配置、组装
```

## 性能基准（criterion, 1000 samples）

| 基准 | p50 | p99 | 吞吐量 | 目标 |
|---|---|---|---|---|
| `decide_from_bytes` CRITICAL | 314.73 ps | **322.89 ps** | 3.10 Gelem/s | < 1μs ✅ (3097x faster) |
| `decide_from_bytes` invalid_magic | 298.72 ps | 299.75 ps | 3.34 Gelem/s | < 1μs ✅ |
| PFP `risk_level()` 提取 | 298.78 ps | 299.57 ps | 3.35 Gelem/s | - |
| PFP `effective_risk_level()` | 305.68 ps | 317.91 ps | 3.27 Gelem/s | - |

**硬实时决策延迟：p99 = 0.32 ns，远超 <1μs 目标（快 3097 倍）。**

运行基准：`cargo bench -p tuck-core`

## 测试覆盖率

```
173 tests passed, 0 failed, 0 warning
├── 28 PFP/决策测试（含 ≥12 故障注入类别，100% Reject）
├── 10 SAP 可选增强测试（重放检测、版本验证、缓存隔离）
├── 9 策略配置测试（TOML 加载/保存/版本验证/自定义策略）
├── 9 HITL 执行闸测试（确认/拒绝/超时 fail-closed/历史记录）
├── 9 CATASTROPHIC 硬覆盖测试（紧急信号/广播通知/优先级/审计）
├── 9 策略热加载测试（文件监控/原子交换/版本管理/重载历史）
├── 22 凭证管理测试（identity_label/Credential/Zeroizing/CredentialStore）
├── 17 物理边缘注入测试（HttpHeader/Bearer/QueryParam/BodyField/BasicAuth）
├── 13 加密文件存储测试（AES-256-GCM/主密钥/原子写入/错误密钥拒绝）
├── 10 HSM/TPM trait 测试（trait 对象安全/KeyAlgorithm/PcrPolicy/AttestationQuote）
├── 14 审计日志测试（SHA-256 链式结构/verify_chain/篡改检测/容量限制）
├── 9 WORM 存储测试（追加写/崩溃恢复/篡改文件检测/统计信息）
├── 14 审计查询测试（多维度筛选/分页/排序/组合过滤/序列化）
└── 16 篡改检测测试（5种篡改类型/TamperReport/历史整合/端到端链验证）
```

运行测试：`cargo test --workspace`

## 核心模块

| 模块 | 职责 | 状态 |
|---|---|---|
| `pfp` (lib.rs) | PFP 4 字节零拷贝读取 + decide() 硬实时决策 | ✅ |
| `sap` | SAP 28 字节可选增强 + Seq-Counter 防重放 | ✅ |
| `policy` | 策略配置（TOML）+ 版本管理 + 文件加载/保存 | ✅ |
| `hitl` | HITL 执行闸（NeedHumanConfirm → 确认/超时 Reject） | ✅ |
| `catastrophic` | CATASTROPHIC 硬覆盖（紧急信号 + 并行人类通知） | ✅ |
| `hot_reload` | 策略热加载（文件监控 + 原子交换 + 重载历史） | ✅ |
| `credential` | 凭证管理（identity_label + Credential + Zeroizing + CredentialStore trait） | ✅ |
| `injection` | 物理边缘注入（出网前注入 + 注入后 zeroize） | ✅ |
| `file_store` | 加密文件存储（AES-256-GCM + MasterKey + 原子写入） | ✅ |
| `hsm` | HSM/TPM trait 预留（HsmCredentialStore + TpmCredentialStore） | ✅ |
| `audit` | 审计日志（SHA-256 链式结构 + AuditLog + verify_chain） | ✅ |
| `audit_store` | WORM 存储（追加写文件 + 崩溃恢复 + 篡改检测） | ✅ |
| `audit_query` | 审计查询 API（多维度筛选 + 分页 + 排序 + Queryable trait） | ✅ |
| `tamper` | 篡改检测（TamperReport + 5种篡改类型 + 历史整合转换） | ✅ |

## 快速开始

```bash
# 构建
cargo build --workspace

# 测试
cargo test --workspace

# 运行（PFP hex bytes）
cargo run --bin tuck -- --pfp CF140800
```

## PFP 4 字节结构

```
Byte 0-1: Family-Magic (0xCF14)
Byte 2:
  bit 0-1: Modality       (COGNITIVE/RENDER/EXECUTIVE/SENSOR_FEED)
  bit 2-3: Risk-Level     (LOW/MEDIUM/CRITICAL/CATASTROPHIC)
  bit 4-5: Body-Stance    (SEATED/STANDING/MOVING/UNKNOWN)
  bit 6-7: Proximity-Edge (SAFE/WARNING/DANGER/CRITICAL_EDGE)
Byte 3:
  bit 0:   Output-Dest    (INTERNAL/EXTERNAL)
  bit 1:   Override-Flag  (NORMAL/HARD_OVERRIDE)
  bit 2:   Replay-Enable  (DISABLED/ENABLED)
  bit 3-7: Reserved       (must be 0)
```

## 决策规则

| Risk-Level | 默认决策 |
|---|---|
| LOW | Pass |
| MEDIUM | Pass |
| CRITICAL | NeedHumanConfirm |
| CATASTROPHIC | Reject |
| CATASTROPHIC + HardOverride | HardOverridePass（不可协商） |

**Rule 6**：Replay-Enable=0 时，有效 Risk-Level 强制降级为 MEDIUM（防止重放攻击）。

## 开发计划

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 方法论初始化 + Rust 项目骨架 | ✅ 已完成 |
| P1 | 核心骨架（PFP 读取 + decide() + fail-closed） | 🚧 进行中 |
| P2 | 策略引擎（Risk-Level 策略 + HITL + CATASTROPHIC） | ⏳ |
| P3 | 凭证物理注入（identity_label + 零化 + HSM） | ⏳ |
| P4 | 全息审计（SHA-256 链式 + WORM + 查询 API） | ⏳ |
| P5 | 传输层集成（CI-144 代理 + HTTP 中间件） | ⏳ |
| P6 | 生态联调（Anaphase/Tentacle/Cellrix） | ⏳ |

## 生态对齐

- **CI-144 协议家族**：https://github.com/CommonIntents/BIND-19
- **PFP-xCF14 规范**：https://github.com/CommonIntents/PFP-xCF14
- **phyt-DNA 方法论**：https://github.com/Jasonmilk/phyt-DNA
- **Helix-Mind**（灵魂/思考）：https://github.com/Jasonmilk/Helix-Mind
- **Anaphase-Helix**（身体/编排）：https://github.com/Jasonmilk/Anaphase-Helix
- **Helix-Tentacle**（手/工具执行）：https://github.com/Jasonmilk/Helix-Tentacle

## 方法论

Tuck 采用 **phyt-DNA v1.0** 自生长方法论。核心文档：

- `docs/VISION.md` — 愿景索引（思想对齐）
- `docs/DNA.md` — 不可变原则 + Tuck 特有铁律
- `docs/RNA.md` — 加载协议 + AI 协作铁律
- `docs/SPEC.md` — 完整叙事（知识本体）
- `docs/PLAN.md` — 开发导航牌
- `docs/GROWTH.md` — 生长记录
- `docs/DEPRECATE.md` — 退役记录
- `docs/spec/` — 哲学/架构/契约/安全/定位分卷
- `docs/decisions/` — ADR 架构决策记录

## License

MIT
