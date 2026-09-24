# ADR-0006: 审计链必须被配置且可验证 —— 出口与账本都不许静默为空

- **状态**: Proposed（待人类批准）
- **日期**: 2026-09-24
- **决策范围**: Tuck 内容治理网关的配置面（`[gateway]`）与运维入口（env 覆盖 / 启动器注入）
- **关联**: `Tuck:ADR-0004`（内容治理网关 · 唯一门）、`Tuck:DNA` 铁律 3（凭证红线）、`Tuck:DNA` 铁律 4（审计不可篡改红线）、`Tuck:DNA` 铁律 5（硬实时路径无分配）；跨仓：`Cellrix:ADR-0045`（探针必须看得见状态行 —— 本 ADR 的验收依赖它）、`anaphase:ADR-0011`（env 注入的既有形状）
- **引用约定**: ADR 编号按仓内序号递增；跨仓引用必须带仓名

---

## 1. 背景

### 1.1 实测：账本路径为空，而网关照常服务

审查当日（本机真进程）：

```
启动日志  {"message":"content-governance gateway serving","addr":"127.0.0.1:60052",
           "upstream":"https://api.deepseek.com/v1","audit":""}
GET /v1/audit?limit=1  → 404 {"error":{"message":"audit chain not configured","type":"no_audit_chain"}}
GET /v1/stats          → 404
```

`[gateway]` 段里只有 `enabled` / `api_key` / `upstream` —— **没有 `audit_path`**。代码路径随之把 `chain` 置为 `None`（`crates/tuck-gateway/src/state.rs:111`），审计查询端点如实返回 `no_audit_chain`（`audit_api.rs:48-54`）。

**注意：404 本身不是缺陷**——它说的是实话。缺陷是**没有人被迫知道**：`up` 的健康检查走的正是 `/v1/audit?limit=1`，而它当时是**状态盲**的（见 `Cellrix:ADR-0045`），于是审计腿整条是死的，而 `up` 打印「Tuck: ✅ 运行中」。

### 1.2 为什么"重建配置"就会丢掉它

`Tuck/config.toml` **被 gitignore**（`Tuck/.gitignore:25`）。本机这份文件的头一行写着「新机重建：模板 + 必改字段」。

⇒ 每次换机器/重建配置，**审计链会静默消失**，因为：
- 模板 `config.example.toml` 的 `[gateway]` 段没有示范 `audit_path`；
- 启动器**没有能力**在不改这个未跟踪文件的前提下注入它 —— `apply_env_overrides()` 是**手写清单**（`crates/tuck-core/src/config.rs:177-205`），只覆盖 `server` / `security` / `audit` / `log`，**完全不认 `gateway.*`**。

⇒ 于是「唯一门」的账本成了**一个人记得才会存在**的东西。这与本生态「配置先于代码、物理事实优先」不符。

### 1.3 同一类缺陷的第二个面

`[gateway] upstream_key`（L2 物理边缘注入）同样为空 ⇒ 调用方的 Authorization 不会被替换成真 key。本 ADR 只处理审计链（可验证的账本），上游注入属于「唯一门」接线（另立 ADR）。

---

## 2. 决策

1. **不发明默认路径。** `audit_path` 保持空 = 不配（诚实），**不**默认成 `/var/log/tuck/...` 或任何硬编码路径（`0 硬编码`）。网关**不**伪造一个空账本来假装健康：`404 no_audit_chain` 保留。
2. **让"没配"在启动时就说出来。** 启动日志已带 `audit` 字段；当 `gateway.enabled && audit_path` 为空时，**升为 WARN 级**，让运维在日志里就能看到门开着而账本没开。
3. **补上 `gateway.*` 的 env 覆盖（仅非机密字段）**：`TUCK_GATEWAY__ENABLED`、`TUCK_GATEWAY__UPSTREAM`、`TUCK_GATEWAY__AUDIT_PATH`。这是本生态既有的 12-factor 形状（`anaphase` 的 `ANAPHASE_TENTACLE_ENDPOINT` 注入，`anaphase-helix/src/config.rs:360-363`：*"injected without touching config.toml — no concurrent file writes, reversible, explicit"*）。⇒ **复用形状，不发明机制。**
4. **机密字段不进 env**：`api_key` / `jwt_secret` / `upstream_key` **不**加 env 覆盖。env 对子进程与 `/proc` 可见，与 `DNA` 铁律 3「明文凭证只在物理注入瞬间存在」相悖。它们继续只住在未跟踪的 0600 配置里。
5. **`config.example.toml` 补上 `audit_path` 的示范与说明**（模板必须让"重建"能得到完整功能）。
6. **启动器注入 `TUCK_GATEWAY__AUDIT_PATH`**，指向工作区内的账本路径（`<workspace>/.helix/tuck/audit.chain`）。启动器不再"只听端口"就宣称 Tuck 就绪 —— 判据改为 `/v1/audit` 返回 **200**（由 `Cellrix:ADR-0045` 使这一点可判）。

---

## 3. 理由

- **单一事实来源**：审计链的位置是**配置**，不是代码里的字面量，也不该是一个人脑中的记忆。给它一条 env 通道，启动器才能成为唯一声明处。
- **物理事实优先**：判据必须是「`/v1/audit` 真的回答了 200 且带 `entries`」，而不是「端口在听」或「配置文件里有这个键」。
- **与既有形状一致**：`TUCK_<段>__<字段>` 的双下划线约定已经写在文档注释里（`config.rs:157-158`），只是实现漏了 `gateway`。本 ADR 是**补全**，不是新机制。
- **不扩大攻击面**：机密走文件（0600、未跟踪），非机密走 env。这条边界正好与 `DNA` 铁律 3 同向。

---

## 4. 不做什么（Non-Goals）

- **不**把 `audit_path` 默认成某个路径。空就是空。
- **不**把 404 改成 200 + 空账本。那会把"没配"伪装成"配了且是空的"，正是本 ADR 要治的冒充。
- **不**为机密加 env 通道。
- **不**在本 ADR 里改上游注入（`upstream_key` / `X-Route-Tier` / 旁路焊死）—— 那是「唯一门」接线，另立 ADR。
- **不**改硬实时 `decide()` 路径。

---

## 5. 影响

- **正向**：`Tuck:ADR-0004` 的"唯一门"重新有账本可查；面板的证轨 Tuck 腿从 404 变为 200；换机重建不再静默丢功能。
- **代价**：`config.example.toml` 与 `config.rs` 的 `apply_env_overrides` 有改动；启动器多一个导出。
- **风险**：env 覆盖**优先于**配置文件（与既有 `server.port` 等一致）。若某部署在 env 里设了 `TUCK_GATEWAY__AUDIT_PATH` 又在文件里设了别的值，env 胜出 —— 这是既有约定，不是本 ADR 引入的。

---

## 6. 验收（判据必须能红 —— 铁律 9）

| # | 判据 | 期望 |
|---|---|---|
| 1 | 单元：设 `TUCK_GATEWAY__AUDIT_PATH` 后 `TuckConfig::load(None)` | `config.gateway.audit_path` == 该值 |
| 2 | 单元：**不设**该 env 时 | 保持文件/默认值（不得被空串清掉） |
| 3 | 单元：设成**空串** | 视为未设（不覆盖）——与既有 `apply_env_overrides` 的"空值忽略"一致 |
| 4 | 活体：带 env 起 `tuck` | `GET /v1/audit?limit=1` → **200**，body 含 `"entries"`；`/v1/stats` → 200 |
| 5 | 活体：不带 env（且配置无 `audit_path`）起 `tuck` | `GET /v1/audit` → **404** `no_audit_chain`（**不得**变成 200） |

**变异注入**：

- 从 `apply_env_overrides` 删掉 gateway 那一段 ⇒ **判据 1 与 4 必红**；还原 ⇒ 转绿。
- 把空串当有效值（去掉 `!v.is_empty()`）⇒ **判据 3 必红**；还原 ⇒ 转绿。
- 判据 5 是**反面对照**：它证明本 ADR 没有把"没配"洗成"健康"。

### 6.1 实测记录（2026-09-24，本机）

**活体，两个方向（`tuck` 真进程，`TUCK_GATEWAY__AUDIT_PATH` 走启动器注入的那条路）：**

| 方向 | `/v1/audit?limit=1` | `/v1/stats` | 账本文件 | 启动 WARN |
|---|---|---|---|---|
| **A** 不注入（且配置无 `audit_path`） | **404** `no_audit_chain` | 404 | 未创建 | **出现**（1 次） |
| **B** 注入 `TUCK_GATEWAY__AUDIT_PATH` | **200** `{"count":0,"entries":[],"queried_by":""}` | 200 | **已打开** | 不出现（0 次） |

⇒ 判据 4 与 5 双向成立；§2.2 的 WARN 在 A 出现、在 B 不出现。

**单元与变异（`cargo test -p tuck-core test_env_override`）：**

| 步骤 | 结果 |
|---|---|
| 改动后 | **3 passed / 0 failed** |
| 变异 1：整段删掉 `gateway.*` env 覆盖 | `test_env_override_gateway_audit_path_both_directions` **变红**；还原 ⇒ 转绿 |
| 变异 2：去掉 `audit_path` 的 `!v.is_empty()` 守卫 | **变红**，且断言如实报出 `left: "" / right: "/from/file.chain"`（空值清掉了文件里的路径）；还原 ⇒ 转绿 |

**回归**：`cargo test --features gateway` 全绿（311 + 42 + 9 + 7 + 4×3 … = **384 tests, 0 failed**）。

**⚠️ 顺带记录一个真实陷阱（本次踩到）**：`crates/tuck/Cargo.toml` 的 `default = []`，所以**裸 `cargo build` 会产出一个不含网关的 `tuck`** —— 它只打印用法就退出。启动器会因此 `wait_port` 失败并 `exit 1`（**是响的，不是静默的**），但开发者本地的二进制会被静默降级。⇒ 构建 Tuck 一律用 `cargo build -p tuck --features gateway`（`README.md:91` 已有此写法，只是容易被忽略）。

---

## 7. 与链路闭环的关系

审计腿是三腿里**唯一有真账本可查**的一条（记忆与执行腿是 Noop，见 `Cellrix:ADR-0045` 的实测）。因此它是「全链路打通」的第一个可观测证据：一轮真实对话之后，`/v1/audit` 应当能按 `trace_id` 查到这一轮的请求与响应。

⇒ **顺序：`Cellrix:ADR-0045`（判据）→ 本 ADR（账本）→ 记忆/执行腿接线。**
