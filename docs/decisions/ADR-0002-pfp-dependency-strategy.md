# ADR-0002: PFP 类型依赖策略 — 本地零拷贝实现 vs 直接依赖 bind19 crate

> **状态**：Active
> **日期**：2026-08-29
> **决策者**：Jasonmilk
> **关联阶段**：P1-T1
> **前置 ADR**：ADR-0001（Rust 重构 + 思想重新对齐）

---

## 背景（Context）

Tuck 是 CI-144 PFP-xCF14 的第一个消费者。PFP 4 字节类型是 Tuck 硬实时决策路径的核心输入。

BIND-19 仓库（https://github.com/CommonIntents/BIND-19，v2.0-alpha 分支）已提供完整的 Rust 参考实现，包含 `bind19::pfp::PfpHeader` 类型。Tuck 需要决定：直接依赖 bind19 crate 复用其 PFP 类型，还是保留本地零拷贝实现。

### BIND-19 PfpHeader 的特点

- **完整 struct 解码**：`decode(&[u8; 4]) -> PfpHeader`，将 4 字节解码为 8 个公共字段（modality/risk_level/body_stance/proximity_edge/output_dest/override_flag/replay_enable/reserved）
- **API**：`encode()`/`decode()`/`verify_magic()`/`is_catastrophic_override()`/`effective_risk_level()`/`has_unknown_reserved()`
- **枚举**：`Modality`/`RiskLevel`/`BodyStance`/`ProximityEdge`/`OutputDest`/`OverrideFlag`，使用 `from_bits()`/`to_bits()` 方法
- **依赖**：dashmap、ed25519-dalek、rand、sha2（传递依赖）
- **edition**：2024（需要 Rust 1.85+）

### Tuck 本地 PfpHeader 的特点

- **零拷贝存储**：`{ raw: [u8; 4] }`，只存储原始字节，不预解码
- **惰性提取**：字段通过方法（`risk_level()`/`override_flag()` 等）位运算按需提取
- **API**：`from_bytes() -> Result<Self, TuckError>`（验证 magic + reserved）/`as_bytes()`/字段提取方法/`effective_risk_level()`
- **枚举**：使用 `From<u8>` trait，`#[repr(u8)]`
- **依赖**：仅 thiserror、zeroize（极轻量）
- **edition**：2021

---

## 决策（Decision）

**tuck-core 保留本地零拷贝 PfpHeader 实现，不直接依赖 bind19 crate。**

理由：

1. **硬实时路径优化**：Tuck 的 `decide()` 函数只需要 `risk_level` 和 `override_flag` 两个字段。本地零拷贝实现避免了完整 struct 解码的开销（8 个字段的位运算提取），只在需要时提取特定字段。`decide()` 的 p99 延迟目标 < 1μs，零拷贝是关键优化。

2. **极致解耦**：tuck-core 是硬实时核心，应该保持极轻量（仅 thiserror + zeroize）。引入 bind19 会带来 dashmap、ed25519-dalek、rand、sha2 等传递依赖，增加编译时间和依赖体积，违背"core 无网络依赖、极轻量"的架构原则。

3. **协议规范复用，而非代码复用**：Tuck 本地 PfpHeader 完全复用了 CI-144 PFP 的协议规范（4 字节布局、字段偏移、枚举值、Family-Magic 0xCF14、Rule 6 降级、CATASTROPHIC 硬覆盖）。这是"极致复用"的正确含义——复用规范，而非盲目复用代码。实现层面根据硬实时需求做优化是合理的。

4. **API 稳定性**：BIND-19 仍在 v2.0-alpha 阶段，API 可能变化。直接依赖 git 分支会导致 Tuck 编译被 BIND-19 的 API 变化破坏。本地实现提供了稳定的接口，在 BIND-19 发布稳定版（crates.io）后再评估切换。

5. **转换桥接**：在需要与 bind19 互操作时（如 tuck-proxy 层 P5），可以通过 `From`/`TryFrom` trait 实现类型转换，不影响 tuck-core 的轻量性。

---

## 备选方案（Alternatives）

### 方案 A：直接依赖 bind19 crate（已否决）

- **优点**：代码复用，与协议规范权威实现保持一致，无需维护本地 PFP 类型
- **缺点**：传递依赖过重（dashmap/ed25519-dalek/rand/sha2），完整 struct 解码增加硬实时路径开销，API 不稳定（alpha 阶段），违背 core 极轻量原则

### 方案 B（选择）：本地零拷贝实现 + 协议规范复用

- **优点**：硬实时路径最优（零拷贝、惰性提取），core 极轻量（仅 thiserror + zeroize），API 稳定，协议规范完全复用
- **缺点**：需要维护本地 PFP 类型（但协议规范已冻结，维护成本低），与 bind19 互操作时需要类型转换

### 方案 C：tuck-core 定义 trait，bind19 实现（过度设计）

- **优点**：抽象接口，可插拔实现
- **缺点**：trait 对象增加运行时开销，违背硬实时路径"无动态分发"原则，过度设计

---

## 放弃了什么（What We Give Up）

1. **直接代码复用**：不直接使用 bind19::pfp::PfpHeader，需要维护本地实现
2. **自动同步**：BIND-19 的 PFP API 变化不会自动同步到 Tuck，需要手动跟进
3. **传递依赖的功能**：不引入 dashmap（并发缓存）、ed25519-dalek（签名验证）等，这些功能在后续阶段（P2/P4）需要时单独引入

---

## 后果（Consequences）

### 正面后果

- tuck-core 保持极轻量（仅 thiserror + zeroize），编译快，依赖少
- `decide()` 硬实时路径零拷贝、惰性提取，p99 < 1μs 目标可实现
- API 稳定，不受 BIND-19 alpha 阶段变化影响
- 协议规范完全复用（4 字节布局、字段偏移、枚举值、Rule 6、CATASTROPHIC 硬覆盖）

### 负面后果

- 需要维护本地 PFP 类型（协议规范已冻结，维护成本低）
- 与 bind19 互操作时需要类型转换（在 tuck-proxy 层 P5 处理）
- BIND-19 的 PFP bug fix 不会自动同步，需要手动跟进

---

## 未来迁移条件

当以下条件全部满足时，重新评估是否切换到 bind19 crate：

1. BIND-19 发布稳定版到 crates.io（≥ v1.0.0）
2. BIND-19 提供零拷贝 PFP 视图类型（如 `PfpView<'a>`，存储原始字节引用，惰性提取）
3. BIND-19 的 PFP 模块可通过 feature flag 独立启用（不引入 dashmap/ed25519-dalek 等传递依赖）
4. 性能基准显示 bind19 的 PFP 类型在 Tuck 硬实时路径中 p99 < 1μs

---

## 实施追踪（Implementation Tracking）

| 任务 | 状态 | 关联提交 |
|---|---|---|
| tuck-core 保留本地 PfpHeader（零拷贝、惰性提取） | ✅ | P0 |
| Rule 6 降级实现（Replay-Enable=0 → 强制 MEDIUM） | ✅ | P0 |
| CATASTROPHIC 硬覆盖实现 | ✅ | P0 |
| fail-closed（from_bytes 验证 magic + reserved） | ✅ | P0 |
| ADR-0002 记录依赖策略 | ✅ | P1-T1 |
| tuck-proxy 层 bind19 互操作（类型转换） | ⏳ | P5 |
| 未来迁移评估（BIND-19 稳定版后） | ⏳ | 待定 |

---

## 参考（References）

- BIND-19 PFP 实现：https://github.com/CommonIntents/BIND-19/blob/v2.0-alpha/src/pfp.rs
- CI-144 PFP-xCF14 规范：https://github.com/CommonIntents/PFP-xCF14
- ADR-0001：Tuck Rust 重构 + 思想重新对齐

---

*ADR-0002 完。*
