# ADR-0001: Tuck Rust 重构 + 思想重新对齐为免疫系统

> **状态**：Active
> **日期**：2026-08-29
> **决策者**：Jasonmilk
> **关联阶段**：P0（方法论初始化 + Rust 骨架）

---

## 背景（Context）

Tuck 最初定位为"AI 会话版本控制/时间穿梭机/多模型网关/人格芯片注入"（Python beta，archive/python-beta/）。随着 Helix 生态的发展，CI-144 协议家族（PFP-xCF14 + SAP-xCF14 + BIND-19）的建立，Tuck 的真正定位逐渐清晰——它应该是 Helix 生态的**免疫系统/无情闸门**，是 CI-144 血液的第一个 PFP 消费者。

Python beta 的哲学不成熟，与生态定位不一致，且 Python 无法满足硬实时（亚微秒级决策）、内存安全、零成本抽象的要求。需要进行 Rust 重构，并重新对齐思想。

---

## 决策（Decision）

1. **思想重新对齐**：Tuck 从"AI 会话版本控制"重新定位为"Helix 生态免疫系统/无情闸门"
2. **语言选择**：Rust（硬实时 + 内存安全 + 零成本抽象 + 无 GC）
3. **CI-144 消费方式**：直接依赖 BIND-19 Rust 参考实现（PFP 4 字节类型），不自己实现帧解析
4. **workspace 结构**：多 crate（tuck-core / tuck-policy / tuck-credential / tuck-audit / tuck-proxy / tuck），core 无网络依赖
5. **方法论**：启用 phyt-DNA v1.0 方法论
6. **Python beta**：移入 archive/python-beta/ 保留为历史参考，不再维护

---

## 备选方案（Alternatives）

### 方案 A：继续 Python beta，逐步改进

- **优点**：已有代码基础，无需重写
- **缺点**：Python 无法满足硬实时（亚微秒级）、内存安全、无 GC 要求；哲学定位不一致，改进等于重写；GIL 限制并发

### 方案 B：Go 重构

- **优点**：并发原生、编译快、部署简单
- **缺点**：GC 延迟影响硬实时；无零成本抽象；内存安全不如 Rust；生态中其他组件（Anaphase/Tentacle）都是 Rust

### 方案 C（选择）：Rust 重构 + 思想重新对齐

- **优点**：硬实时（亚微秒级）、内存安全、零成本抽象、无 GC、与生态其他组件（Anaphase/Tentacle）同语言、可复用 BIND-19 参考实现
- **缺点**：学习曲线陡、编译慢、需要重新设计架构

---

## 放弃了什么（What We Give Up）

1. **Python beta 的所有代码**：Tuck/、personas/、pyproject.toml 全部移入 archive，不复用
2. **"AI 会话版本控制"定位**：人格芯片、时间穿梭、多模型网关等功能全部放弃，Tuck 专注于安全闸门
3. **快速原型能力**：Python 的快速迭代能力，Rust 编译慢但运行快
4. **向后兼容**：Rust v2.0 不兼容 Python beta API，这是思想重新对齐后的重构，不是版本升级

---

## 后果（Consequences）

### 正面后果

- Tuck 成为 CI-144 PFP 的第一个消费者，验证了 PFP 4 字节设计的实用性
- 硬实时决策（p99 < 1μs），满足生态安全闸门要求
- 与 Anaphase/Tentacle 同语言，生态集成无缝
- 内存安全，无 GC，适合安全关键系统
- 思想对齐后，Tuck 在生态中的角色清晰，不再是"什么都做的工具"

### 负面后果

- 需要从头开始，P0-P6 完整开发周期
- Python beta 用户需要迁移，无向后兼容
- Rust 学习曲线，贡献者门槛提高
- 编译时间长，开发迭代速度降低

---

## 实施追踪（Implementation Tracking）

| 任务 | 状态 | 关联提交 |
|---|---|---|
| P0 方法论初始化（VISION/DNA/RNA/SPEC/PLAN/GROWTH/DEPRECATE + spec/ + ADR） | ✅ | P0-T1 |
| P0 Rust 项目骨架（Cargo.toml + workspace + src/lib.rs） | 🚧 | P0-T2 |
| P0 CI-144 依赖接入 | ⏳ | P0-T3 |
| P0 基础类型定义（Decision/TuckError/Config） | ⏳ | P0-T4 |
| P1 核心骨架（PFP 读取 + decide() + fail-closed） | ⏳ | P1 |
| P2 策略引擎（Risk-Level 策略 + HITL + CATASTROPHIC） | ⏳ | P2 |
| P3 凭证物理注入（identity_label + 零化 + HSM） | ⏳ | P3 |
| P4 全息审计（SHA-256 链式 + WORM + 查询 API） | ⏳ | P4 |
| P5 传输层集成（CI-144 代理 + HTTP 中间件） | ⏳ | P5 |
| P6 生态联调（Anaphase/Tentacle/Cellrix） | ⏳ | P6 |

---

## 参考（References）

- CI-144 PFP-xCF14 规范：https://github.com/CommonIntents/PFP-xCF14
- BIND-19 参考实现：https://github.com/CommonIntents/BIND-19 (v2.0-rc.1)
- phyt-DNA 方法论：https://github.com/Jasonmilk/phyt-DNA
- Helix 生态全景：Helix-Mind + Anaphase-Helix + Helix-Tentacle + Cellrix

---

*ADR-0001 完。*
