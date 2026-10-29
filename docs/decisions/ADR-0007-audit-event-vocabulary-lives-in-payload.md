# ADR-0007: 审计事件词汇住在 payload 里 —— 链层冻结，只许追加

- **状态**: Proposed（待人类批准）
- **日期**: 2026-10-28
- **决策范围**: 审计链**形状**（不是审计策略、不是治理矩阵、不是行为面）
- **关联**: `Tuck:ADR-0004`（内容治理网关 · D4 账本 crate 零行业词汇 / D5 Rosetta 规则 / D6 Ed25519 锚定）、`Tuck:ADR-0006`（审计链必须被配置且可验证）、`Tuck:DNA` 铁律 4（审计不可篡改红线）
- **引用约定**: ADR 编号按仓内序号递增；跨仓引用必须带仓名

---

## 1. 背景

### 1.1 实测：仓里有**两条**哈希链，形状互斥，方案要冻的那条原本没被指名

| | **链 A**（生产） | **链 B**（静置） |
|---|---|---|
| 代码 | `crates/tuck-audit/src/lib.rs` | `crates/tuck-core/src/audit.rs` + `audit_store.rs` |
| 记录 | `AuditRecord { seq, ts, payload, prev_hash, hash }`（`lib.rs:100`） | `AuditEntry { entry_id, timestamp, decision, risk_level, modality, override_flag, source, identity_label, prev_hash, hash }`（`audit.rs:52`） |
| 哈希前像 | `serde_json::to_vec(&(seq, ts, payload, prev_hash))`（`lib.rs:118`） | 9 个字段逐个 `hasher.update`（`audit.rs:81-95`） |
| 行业词汇 | **零**（ADR-0004 D4：「策略词汇不污染账本 crate」） | 满（decision / risk_level / modality / override_flag 全是 PFP 词汇） |
| 在生产通路上 | **是** — `crates/tuck/src/main.rs:142` `tuck_audit::AuditChain::open(&gw.audit_path)`；`crates/tuck-gateway/src/ledger.rs:30` `record()` → `chain.append(…)` | **否** — `crates/tuck/src/main.rs:16` 只 import `config::TuckConfig, decide_from_bytes, SecurityPolicy` |
| 现在谁在用 | 全请求/响应记录 | `crates/tuck-core/benches/integration_benchmark.rs:10`、`crates/tuck-core/src/status.rs:26` |

复跑：

```
grep -n 'tuck_core' crates/tuck/src/main.rs
# 16:use tuck_core::{config::TuckConfig, decide_from_bytes, SecurityPolicy};
grep -rn 'AuditLog\|AuditEntry' --include=*.rs crates/ | grep -v 'audit.rs\|audit_query.rs\|tests/'
```

**为什么这必须先指名**：「冻结 `audit_event` schema v1」这句话在两条链并存时是不确定的。两份形状互斥（`decision`/`risk_level` 在 B 是顶层字段，在 A 只是 `payload` 里的自由内容）。若不指名就按七类事件设计，最可能的结局是**冻在一台没接电的机器上**（链 B 只有 bench 在用）。

### 1.2 前像事实：链 A 的 `payload` 是自由的，这正是它的价值

`AuditRecord` 的 canonical 前像是 `(seq, ts, payload, prev_hash)`，而 `payload` 是任意 `serde_json::Value`。
⇒ **在 `payload` 内部增删字段，不改前像 ⇒ 不使历史哈希失效。**
⇒ ADR-0004 D4 那句「策略词汇不污染账本 crate」在这一刻兑现：**schema 变成了可增量演进的东西**，不需要一次定死。

### 1.3 反例：链层加字段是**不可逆**的

同一个事实的另一面：把事件词汇做成 `AuditRecord` 的**顶层字段**，前像立刻改变 ⇒ **全链历史哈希当场失效**，且无法回滚（已写出的行不能重算，账本 append-only）。

⇒ 所以本 ADR 要定的**不是**一份 schema，而是**一条禁令 + 一条追加规则**。

### 1.4 追加型账本对"改字段形状"有硬约束

`payload` 里已有字段的形状**不能改**，因为历史行永远保持旧形状，而账本不回溯。仓内已有先例与判据：

```
crates/tuck-gateway/src/audit_api.rs  audit_stats 内注释：
  "历史记录（tier 字段加入前）归入 default——审计链 append-only 不回溯，统计层兼容旧格式"
```

⇒ 先例说明"加字段"可行；但它同时暴露一个必须写死的纪律（见 D3）。

---

## 2. 决策

### D1 · 冻结**链 A**；链 B 静置为 dead-code-in-waiting（不删、不扩）

- 今后一切审计事件词汇、实体级记录、告警判据，**只在链 A（`tuck-audit`）上做**。
- 链 B **不删除**（删除会破坏 `status.rs` 与 benchmark，且不可逆），但：**不得在其上新增字段、不得接回请求路径**。
- 若将来要合并两条链，须单开 ADR（因为合并意味着历史迁移）。

### D2 · 禁令：事件词汇只能落在 `payload`（`kind` + `data`），**禁止升为 `AuditRecord` 顶层字段**

理由见 §1.3：顶层字段 = 改前像 = 全链历史哈希失效 = 不可逆。

判据（将来任何 PR 都要能过）：`tuck-audit` 的 `AuditRecord` 字段集合**只允许是** `{seq, ts, payload, prev_hash, hash}`。这条是可机械检查的（读 `lib.rs:100` 的字段名集合），不需要新仪器。

### D3 · payload 内只许追加，且**缺失必须可判别**

- 既有字段（`kind` / `trace_id` / `data{destination, action, transform, categories, redactions, route_tier, session, caller, status, demap_miss}`）**形状冻结**。
- 新增信息只能加**新键**；不得把 `["P_00"]` 改成 `[{…}]`（那会让同一键有两种形状，且历史行无法迁移）。
- **读者纪律**：字段缺席 ≠ 值为 0。缺席须报 `unknown`（或具名"早于本次记录"），**不许桶进一个编出来的默认值**。`audit_stats` 对 `route_tier` 的 `"default"` 兜底是历史妥协，**不得成为新模式**——它把"当时还没这个字段"读成了"走的是 default 路由"。

### D4 · 事件词汇（`payload.kind`）分两层，互不覆盖

| 层 | kind | 现状 | 说明 |
|---|---|---|---|
| 调用层（既有） | `request` / `response` | 在用，形状冻结 | `ADR-0004:54`（D4 内的**内容枚举**，不是条款） |
| 实体层（新增） | `redact` / `demap` / `mapping` / `policy` / `exempt` / `authz` / `integrity` | 未实现 | 本 ADR 只定名字与承载位置，不批准实现 |

`/v1/audit?kind=` 已支持任意字符串（`audit_api.rs:66`），所以新增 kind **不需要改查询层**。

**补注（不修订 ADR-0004）**：`ADR-0004:54`「每笔调用 2 条记录」是 D4（标题：**审计链 = 唯一账本（不引入第二账本）**）下面的一句**内容枚举**——说明 `request` / `response` 各带什么字段——**不是一条不变式**。D4 的条款是同节另外几行（不引入 Vault/WAL、通用链零行业词汇、0600、seq 从文件尾恢复、Clock 注入）。

⇒ 实体层 kind 是**追加**，与 `ADR-0004:54` 并存，**不需要「修订」它**。本 ADR 的初版把这句描述当成条款去「修订」，属**把描述当规范**（登记见 §3.1）。**ADR-0004 正文一字不改。**

### D5 · 实体级细节走**新的 `kind: "redact"` 记录**，不动 `redactions`；且**不记原文字段**

- `request.data.redactions` 保持 `["P_00", …]`（形状冻结），它是**摘要**，不是实体来源。
- 实体级明细写成单独记录：`{"kind":"redact","trace_id":…,"data":{"session":…,"destination":…,"entities":[{"placeholder":"P_00","category":"mapping"}]}}`。
- **不记原文字段（span）**：`Replacement.start/end` 的语义是「**脱敏后**文本中的位置」（`redact.rs:120-127`）。若改记原文位置，两者之差 = 原实体长度 ⇒ **等价于泄露被打码实体的长度**。要定位就用脱敏文本坐标，原文坐标一律不落盘。
- `category` 是**有信息量**的，不是同义反复：`decide()`（`matrix.rs:165-181`）把命中按 `Guard > Hold > Mapping` 取最高优先类的策略决定 `transform`，但传给 `redact()` 的 `v.hits` 是**全部类别**的命中 ⇒ 同一次 Redact 下可能混着不同 `Category` 的实体。

### D6 · `not_configured` 的形状先定，行为改动另裁

- 形状：`{"kind":"not_configured","data":{"stage":"redact","reason":"no_hits|no_rules|transform_none","session":…,"destination":…}}`，落在链 A。
- **行为**（把 `gov.rs:213` 的 `else` 分支从"静默放行"改成"出声"）属**授权②**，本 ADR 不批准，只登记为待裁。

---

## 3. 顺带查出的既有缺陷（本 ADR 不修，只登记）

`GET /v1/audit?action=block|hold|forward` **恒返回 0 条**：

```
crates/tuck-gateway/src/audit_api.rs:77
    v.get("payload").and_then(|p| p.get("action"))        ← 读不到
实际位置（record() 的包装，ledger.rs:37-41）
    payload = {"kind":…, "trace_id":…, "data": {"action": …}}
crates/tuck-gateway/src/audit_api.rs  audit_stats 里读对了
    data.get("action")
```

危害形状：**一个永远匹配不到东西的过滤器，读起来像"没有这类事件发生"**（同族：读到空当没有）。
`tests/audit_query.rs` 只测了 `trace_id=` 过滤，没有 `action=` 的用例 ⇒ 无判据。

---

## 3.1 本 ADR 自身的修正记录（append-only，原句不删）

### 2026-10-29 · "修订 ADR-0004" → "补注"

初版 D4 写：「ADR-0004『每笔调用 2 条记录』由此**修订为**『2 条调用层记录 + N 条实体层记录（有才写）』」。

**性质判定：错。** 判定依据不是措辞，是 `ADR-0004:53` 的**节标题**：D4 管的是「审计链 = 唯一账本（不引入第二账本）」，`:54` 那行在它下面做**内容枚举**。⇒ 我**把一句描述当成了条款**，于是凭空造出一条需要「修订」的原文；而它本来就**不约束**任何东西。

**同族实例**（本生态已发生过的）：把「400 行是注意力边界」当机器门去实现（`anaphase:ADR-0042` D16/D17）、把 `#[ignore]` 当覆盖、把「端点已定义」当「端点已挂载」（K-133）。共同形状：**把描述读成规范**。

**后果**：若按初版执行，会去动一份已批准、且一字未错的 ADR（`Tuck:ADR-0004`），并凭空造出「2 + N 条」这个需要迁移的历史包袱。

**改正**：D4 改为「**补注**」；`Tuck:ADR-0004` 正文**一字不改**。不变式实际落在本 ADR 的 D2（顶层字段禁令）——它才是能拦人的那条。

**教训（可复用）**：判定「这是条款还是描述」的判据不是措辞（两句都写「必须/2 条」），而是**它所在的节标题管的是什么**。节标题是范围的声明，比句子本身可靠。

---

## 4. 明确不做

```
· 不为审计新建存储（链 A 已在用；ledger/hits-2026.jsonl 是闸门裁决账本，三本账之一，不碰）
· 不把审计事件写进 ledger/hits-2026.jsonl（一个文件两种 schema）
· 不重新设计签名哈希链 / Ed25519 锚定（ADR-0004 D6 已实现，勿再设计）
· 不重做「只写令牌」（ADR-0004 D5 已实现，维护即可）
· 不搞影子期（任何形式：天数 / 问句集 / 告警覆盖率）
· 不把七类事件升为 AuditRecord 顶层字段（D2）
· 不改 `redactions` 的既有形状（D3/D5）
· 不落原文 span（D5）
· 不修订 ADR-0004 的任何一行（`:54` 是描述不是条款，见 §3.1）
```

---

## 5. 待批准

1. D1（冻链 A / 链 B 静置）—— 影响：链 B 从此不再演进。
2. D2（禁令）—— 影响：将来若确需顶层字段，必须先做历史迁移案。
3. ~~D5（新增 `kind:"redact"` 记录）—— 影响：`Replacement` 需带 `category`（`redact.rs:120`，pub 结构，crate 外可见）~~
   ⇒ **已批 2026-10-29（园丁）**：`Replacement` 允许加 1 个字段（`pub category: Category`）。已核成本：`lib.rs:95` `pub use` 对外、构造点 **1 处**（`redact.rs:181`）、工作区内其它构造者 **0**。
   ⇒ 仍不批准的部分：**实体级记录入链**（append-only 不可撤，待 D5 全文批后再写行）。
4. D6 的行为半段（`else` 分支出声）—— **授权②**，另行裁定。

## 6. 2026-10-28 追加：已批一件、待批一件

### 6.1 `Replacement` + `pub category: Category` —— 已批，已落
`crates/tuck-gateway/src/redact.rs` 的 `Replacement` 增加 `widget category`，由 `Hit.category` 填充。
测试：`replacement_carries_the_hit_category_not_a_default`（正样本 Guard ⇒ Guard；
负样本：写死成 `Category` 首个变体 `Mapping` ⇒ 必红）。
可逆性：结构体字段 + 一处构造点（`redact.rs:181`），工作区内其它构造者为 0。
**仍未做**：`Replacement.start/end` 保持「脱敏后文本」坐标，不记原文 span（D5 的理由）。

### 6.2 实体级 `kind: "redact"` 入链 —— 形状提案，**待批，未写行**
- 形状：`{"kind":"redact","trace_id":…,"data":{"session":…,"destination":…,"entities":[{"placeholder":"P_00","category":"mapping"}]}}`
- 语义：一次 redact 调用一条；只写令牌与类别，不写原文、不写原文坐标；
  与调用层 `request`/`response` 并存（ADR-0004「每笔 2 条」⇒「2 + N 条，有才写」）。
- 测试计划：正样本（命中 ⇒ 一条 redact 且 entities 长度 = replacements 长度）；
  负样本（未命中/未启用 ⇒ **零条** 且带 `not_configured` 事件，不许写成「一条空 entities」——
  「什么都没打」与「打了 0 个」是两件事）。
- 不可回滚：链 append-only，一旦写入即永久。故**形状先批、代码后写**；
  若形状将来要改，只能新增 kind，不能改已写入行的含义。

## 7. 2026-10-28 追加：反射类动作的留痕（D7，形状待批，行为未做）

**为什么现在写**：CI-144 的物理执行面（具身机器人、端级反射弧）一旦接入，会出现一类**亚毫秒级、学习得来、跑在快路径**的动作（例：起手式识别 → 躲避）。这类动作天然**不可审计**，而本 ADR 的整个契约假设是「每个动作都能留痕」。现在加词汇是零成本；接上本体再加，就是改落盘结构（K-15 那类迁移）。

**D7（新增，Proposed）**：反射类动作的留痕必须同时给出三件事，缺一不算留痕：

| 字段 | 回答的问题 | 缺席的后果 |
|---|---|---|
| 触发条件（起手式 / 传感阈值越界） | 为什么动 | 事后无法解释 |
| 反射 ID + 版本 | 谁决定的 | 无法归因到某一条学到的反射 |
| 结果（执行 / 未执行 / 被否决） | 动没动 | 「没触发」与「触发了但没动」不可区分 |

**落点**：仍是 `payload.kind`（D2 禁令内），新增 `kind: "reflex"`；**不得**升为 `AuditRecord` 顶层字段。

**性能约束（与 D7 同等效力）**：留痕**不得**在快路径上同步落盘。形态＝内存环形缓冲 + 异步落盘 + **有界丢弃且丢弃数可审计**。缓冲满时丢最旧者；丢弃计数必须作为一条 `kind: "reflex"` 的汇总事件落链。否则「留痕」本身违背 <100ns 的快路径约束，或者为不丢而阻塞、把反射弧拖成慢路径。

**明确不做（本轮）**：不实现 `kind: "reflex"` 的写入、不改 `gov.rs`、不引入缓冲结构。本条只定形状与约束，等物理执行面立项再实现。
