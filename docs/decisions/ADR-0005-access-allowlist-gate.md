# ADR-0005：访问白名单——scope→capability 的准入闸门

- **状态**: Accepted（2026-09-15 用户批准）
- **日期**: 2026-09-15
- **决策范围**: Tuck（网关准入层）/ CI-144（capability 命名空间）/ Anaphase（调用方，经 scope 声明）
- **关联**: `Tuck:ADR-0004`（内容治理网关）、`Tuck:ADR-0001`（Rust 重建对齐）、
  CAPABILITY-13 spec §2.1（scope→capability 映射）、`anaphase:ADR-0036`（physical model）
- **跨仓引用一律仓名限定**：`Tuck:ADR-0004` 与 `anaphase:ADR-0036` 分属两仓。

## 1. 背景与问题

ADR-0004 回答的是「payload 里有什么」：检测 → 政策 → 混淆/拦截 → 审计。
它**没有**回答「这个请求能去哪」。

现状：请求只要内容干净，就能到任何 `[[gateway.upstreams]]`（agnes / openrouter），
模型名亦无约束。缺口有三：

1. **无目的地准入**。供应商与模型都不可收敛，新增 upstream 即自动对所有调用方开放。
2. **无调用方维度**。虽有 `api_key` 与 JWT，但鉴权通过即全放行 —— 认证不等于授权。
3. **拒绝不可观测**。没有「谁想去哪、被哪条规则挡下」的记录。

需求（用户 2026-09-15）：白名单、黑名单、LLM 维度、语义混淆（行业黑话映射表）、
警报、通知、拦截，**优先兼容 CI-144**。

### 已有槽位（不新建实体）

| 现有 | 可复用 |
|---|---|
| `gov.rs::AuthConfig` | `api_key = None` 即 fail-closed；JWT **`scope` claim 已在转发进审计链** |
| `matrix.rs` | `Destination` / `Action` / `Verdict.alert`，优先级 block > hold > pass |
| `policy.rs` | `mapping` category = 语义混淆（ADR-0004 已落，见 D9） |
| `hitl.rs` | 挂起与人工确认通道 |
| `[hot_reload]` | 映射表热加载通道已存在 |

### 前沿实践的结论（借模式，不借名号）

- **default-deny + 显式清单**是防 agent 数据外泄最有效的**确定性**控制：
  模型可被完全诱导，但网络/代理层不允��就是不允许。
- **每次拒绝都要记录** —— 被拦下的请求既是误配置的信号，也是攻击的信号。
- **白名单不解决白名单内滥用**：目标在清单内仍需 scoped credential 约束，两者互补。
- **配置期失败优于运行期失败**：清单解析不出来就拒绝启动，不要在运行期降级放行。

## 2. 决策

### D1｜准入是独立闸门，不并入内容矩阵

内容治理回答「有什么」，准入回答「能不能去」。两个关注点。
`decide()` 已经正交（`{action} × {transform} × {alert}`），不再往里加维度。

```text
request ─► [admit: 这个 scope 能否访问这个 capability？]
             ├─ deny → 403 + 审计（reason 进 body 与审计链）
             └─ allow ─► detect → decide → redact → forward
```

闸门在 `detect` **之前**：不允许的目的地，连内容都不必读。

### D2｜清单形态复用 CAPABILITY-13 的 `scope → capability[]`

不新造清单格式。CI-144 已有：

```toml
[mappings.standard_scopes]
"external_network" = ["network:outbound"]
[mappings.custom_scopes]
"scientific_simulation" = ["compute:float_matrix", "filesystem:read:/opt/data"]
```

Tuck 沿用同一形态：**判定 = 本次请求所需 capability 是否属于该 scope 的 capability 集合**。
JWT `scope` claim 已在审计链上，无需新增载体。

### D3｜LLM 维度用 CI-144 三段式 `domain:action[:qualifier]`

| capability | 含义 | 取数来源 |
|---|---|---|
| `llm:egress` | 允许出网调 LLM（粗粒度） | 路由面 |
| `llm:invoke:<supplier>` | 允许访问某供应商 | `X-Route-Tier` → `upstreams[].tier` |
| `llm:model:<model>` | 允许调用某模型 | **请求 body 的 `model`** |

模型名取**上游请求 body**，不取 config 声明 —— 与 `anaphase:ADR-0036` physical model
同构（物理事实优先）。拿不到 `model` 时按 `default_action` 处理，**不猜**。

三段式语法与通配规则本身来自配置（见 D11），本 ADR 不固化任何字面量。

### D4｜白名单与黑名单：同一命名空间、同一张表

一条策略 = `{ scope, capability, effect }`，`effect ∈ {allow, deny}`。
**不建两张表** —— 一份事实一个来源，拆成 allow 表与 deny 表就会出现同一 capability
两处声明、优先级靠约定而非数据。

**deny 优先**：任何 deny 命中即拒绝。与 `matrix` 的 `block > hold > pass` 同构，
fail-closed 优先级不重新发明。

### D5｜默认 deny，可配置

`[access] default_action = "deny"`（默认），可选 `"allow"`。

默认值取 deny 的理由：前沿实践的基线是 default-deny；且 Tuck 既有哲学已是
「无凭证即无访问」（`api_key = None` ⇒ deny all）。**清单为空 ⇒ 拒绝全部**，
与之一致：没配好就是不能开门，不是开门。

做成配置项而非写死，是为了容纳「先观察后收紧」的部署阶段 —— 但**默认值必须安全**。

### D6｜配置期失败 > 运行期失败

策略表解析失败、capability 语法非法、签名校验不过 ⇒ **启动失败**。
与 `RuleSet::compile` 的 invalid-regex 硬错误同构：错误在配置期暴露，
不在请求路径上犹豫。

### D7｜拒绝是一等公民，必须进审计链

每次 deny 记录：`who(scope)` / `what(capability)` / `which(target)` / `why(rule_id)`。
拒绝不是异常路径，是**信号源**：既暴露误配置，也暴露探测行为。

### D8｜警报复用 `Verdict.alert`，通知只给通道不给实现

- **警报**：`Verdict.alert` 已存在，准入层沿用同一字段，不新增第二套。
- **通知**：新增**可插拔 sink**，定义为 trait + 配置驱动。**默认无实现、不配置就不发**。
  不内置任何具体通道（webhook / 邮件 / 队列）—— 那是部署方的选择，不是网关的预设。

### D9｜语义混淆（行业黑话映射表）沿用 ADR-0004，本 ADR 只补热加载

ADR-0004 已决策 Cyber Camouflage（`mapping` category：实体 → 占位符）。
**不另起炉灶**。本 ADR 对它只做一件事：映射表接入既有 `[hot_reload]`，
使行业黑话语料可在线更新而不重启。

行业黑话是**配置数据**，不是机制 —— 语料更新不该触发发版。

### D10｜拦截沿用既有 `Action::Block`

不新增第四种动作。`pass / block / hold` 三态已覆盖：准入拒绝归入 `block`，
需要人工确认的边界情形归入 `hold`（复用 `hitl.rs`）。

### D11｜0 硬编码 + 确定性

- capability 前缀、语法、通配规则全部来自配置或常量表，代码内零字面量。
- 准入判定是**纯函数**：无网络、无时钟、无全局状态 ⇒ 同输入同输出，可回放。

## 3. 备选方案

| 方案 | 否决理由 |
|---|---|
| 并入 `matrix` 作为新维度 | 两个关注点混一张表；`decide()` 的正交性被破坏，且准入不该等检测跑完 |
| 在网络层做（iptables / CNI 策略） | Tuck 是应用层网关；且 LLM 维度要读 body 的 `model`，网络层看不见 |
| 每个 upstream 加一个开关 | 无法表达 scope 维度；配置散落，新增上游要改多处 |
| 自造清单格式 | 违反「优先兼容 CI-144」；CI-144 的 `scope→capability` 已是现成形态 |

## 4. 放弃了什么

- **放弃网络层强制**。Tuck 只管自己这道门，不管宿主网络策略 —— 两者互补，不互相替代。
- **放弃含义级判断**。沿用 ADR-0004：Tuck 判字符串，不判含义。准入同样只判 capability 字面量。
- **放弃内置通知实现**。只给 sink 通道，具体通道由部署方注入。
- **放弃运行期优雅降级**。配置错误就启动失败，不允许「先跑起来再说」。
- **放弃按 IP / CIDR 的准入**。Tuck 的调用方身份由 CI-144 scope 表达，IP 是另一个层的事实。

## 5. 后果

**正面**：目的地可收敛；scope 维度原生（CI-144 兼容）；拒绝可审计、可告警；default-deny 兜底。

**代价**：
1. **配置负担**。每新增供应商或模型，必须先写进白名单才能用 —— 这是 default-deny
   的固有成本，前沿实践也承认它，只是认为收益远大于摩擦。
2. **白名单内滥用不解决**。目标在清单内时，本闸门放行。需 scoped credential
   （上游 key 按 supplier 隔离，现状已满足）与内容治理（ADR-0004）配合。
3. **一次行为变更**。上线后未列入清单的调用会开始失败 ⇒ T1–T7 中须包含
   **观察模式**（记录但不拦），使收敛过程可度量。

## 6. 实施追踪

| # | 任务 | 状态 |
|---|---|---|
| T1 | 策略表结构与解析器（配置期 fail-closed，非法即启动失败） | ⬜ |
| T2 | 准入闸门接入 `gov.rs` pipeline（置于 `detect` 之前） | ⬜ |
| T3 | capability 命名空间常量表（`llm:egress` / `llm:invoke` / `llm:model`） | ⬜ |
| T4 | 审计链扩字段：`scope` / `capability` / `rule_id` / `effect` | ⬜ |
| T5 | 通知 sink trait + 配置（默认无实现） | ⬜ |
| T6 | 观察模式（`default_action` 之外独立的 `observe_only` 开关，只记不拦） | ⬜ |
| T7 | 测试：A/B（先证伪后证实）+ 变异测试证明非空转 | ⬜ |
| T8 | 文档：`config.example.toml` 补 `[gateway]` 与 `[access]` 段（example 已漂移）、PLAN / GROWTH | ⬜ |

**顺序硬约束**：T1 → T2（无表则无门可加）；T6 可并行但**必须在首次上线前**可用。

## 7. 参考

- `Tuck:ADR-0004` —— 内容治理网关（语义混淆 / 拦截 / 告警的归属）
- `Tuck:ADR-0001` —— Rust 重建对齐
- CAPABILITY-13 spec §2.1 —— `scope → capability[]` 映射与 Ed25519 签名
- `anaphase:ADR-0036` —— physical model（模型名取上游响应）

---

*准入管「能去哪」，治理管「带什么出去」。两道门，各管一件事。*
