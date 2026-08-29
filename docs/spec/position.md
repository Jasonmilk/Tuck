# 生态定位（position）

> **所属方法论**：phyt-DNA v1.0
> **性质**：Tuck 在生态中的定位。独立通用 + Helix 原生优先。

---

## 定位声明

**Tuck 是 CI-144 协议家族的第一个 PFP 消费者，是 Helix 生态的免疫系统/无情闸门。它不是"安全工具"，不是"审计插件"，不是"可选的增强组件"——它是数字生命体生存的底线。**

**核心定位**：独立通用 + Helix 原生优先。Tuck 可独立用于任何 CI-144 兼容系统，Helix 生态是第一公民。

---

## 生态组件关系

| 组件 | 职责 | 与 Tuck 的关系 |
|---|---|---|
| **Helix-Mind** | 思考、认知工艺、记忆 | Tuck 不被 Mind 直接调用；Mind 的意图通过 Anaphase 编排，经过 Tuck 过滤 |
| **Anaphase-Helix** | 编排、调度、状态机 | Anaphase 产生的 CI-144 帧经过 Tuck 过滤；Anaphase 接收 Tuck 的决策结果 |
| **Helix-Tentacle** | 工具执行、沙箱、信息觅食 | Tentacle 的出网请求经过 Tuck 过滤；凭证由 Tuck 注入 |
| **Cellrix** | 观测、渲染、语义投影 | Cellrix 展示 Tuck 的决策状态和审计日志 |
| **Helix-Callosum** | 上下文压缩、已见熵 | 与 Tuck 无直接关系（Tuck 不参与认知工艺） |
| **CI-144 / BIND-19** | 血液/通信协议 | Tuck 是 PFP-xCF14 的第一个消费者；Tuck 读取 PFP 做决策 |
| **phyt-DNA** | 方法论锚点 | Tuck 采用 phyt-DNA v1.0 方法论 |

---

## 对齐链

```
Tuck（免疫系统）
    ↓ 消费
PFP-xCF14（CI-144 冻结层，4字节物理特征）
    ↓ 属于
CI-144 协议家族（血液）
    ↓ 服务
Helix 生态（数字生命体）
    ↓ 认知真相源
Helix-Mind（灵魂/思考）
```

---

## 独立可用性

Tuck 可独立用于任何 CI-144 兼容系统，不依赖 Helix 生态其他组件。

| 使用场景 | 是否需要 Helix 其他组件 | 说明 |
|---|---|---|
| CI-144 帧代理 | 否 | 任何 CI-144 帧都可经过 Tuck 过滤 |
| HTTP 反向代理 | 否 | 非 CI-144 系统也可用 Tuck 作为安全网关 |
| 库模式嵌入 | 否 | `use tuck_core::decide` 嵌入任何 Rust 项目 |
| Helix 生态全自动 | 是（Anaphase + Tentacle + Cellrix） | 完整生态集成，端到端安全 |

---

## 生态接入硬性验收

| 验收项 | 标准 | 状态 |
|---|---|---|
| PFP 消费 | 直接使用 BIND-19 `PfpHeader` 类型，不自己实现帧解析 | ✅ 设计确认 |
| CI-144 帧兼容 | 支持 BIND-19 v2.0 帧结构（PFP + SAP + 载荷） | ✅ 设计确认 |
| identity_label 兼容 | 与 Anaphase/Tentacle 的 identity_label 格式一致 | ✅ 设计确认 |
| 审计日志兼容 | 审计日志可被 Cellrix 消费和展示 | ⏳ P5 传输层集成时确认 |
| HITL 执行闸兼容 | NeedHumanConfirm 决策可被 Anaphase 接收并触发人类确认 | ⏳ P2 策略引擎时确认 |

---

## 与 Python beta 的关系

- **Python beta**（archive/python-beta/）：早期定位为"AI 会话版本控制/时间穿梭机/多模型网关/人格芯片注入"，哲学不成熟，与 Helix 生态定位不一致
- **Rust v2.0**（当前 rs 分支）：思想重新对齐为"免疫系统/无情闸门"，极致复用 CI-144，是 Helix 生态的安全底线
- **关系**：v2.0 不是 Python beta 的延续，而是思想重新对齐后的重构。Python beta 保留为 archive 历史参考，仅供考古

---

*《生态定位》v2.0 完。*
