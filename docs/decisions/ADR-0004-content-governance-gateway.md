# ADR-0004：内容治理网关——Tuck 的差异化本体

- **状态**: Accepted
- **日期**: 2026-09-07
- **决策范围**: Tuck（网关 + 审计链）/ Anaphase（唯一出口）/ FlowModus（调度在 Tuck 上方）
- **关联**: ADR-0001（Rust 重建对齐）、ADR-0003（Cellrix 状态流）、ECOSYSTEM.md（CI-144 全局治理）

## 1. 背景与问题

P0-P7 完成后 Tuck 具备 PFP 亚微秒决策、fail-closed、凭证注入与蓝图级审计。
但存在一个存在论问题：**只有 CI-144 能力的 Tuck 与普通网关无异**——路由、认证、
日志是任何网关都有的。内容治理才是 Tuck 的不可替代性：

- 用户明确要求：**本地与外网 LLM 都需要管理与审计**（不只是出网方向）；
- 语义混淆（映射表）与敏感拦截（告警/拦截/挂起）在 beta 版已验证（Cyber Camouflage）；
- "如果 Tuck 不能管控 API 内容的输入输出，就只是多了 CI-144 能力的普通网关"。

另外，PLAN P4"全息审计"此前标记已完成，但 crates 中并无 tuck-audit——那是蓝图先行。
本 ADR 同时兑现 P4 承诺（SHA-256 链 + 篡改检测）并升级为**内容治理网关**。

## 2. 决策

### D1: 内容治理 = Tuck 的差异化核心
Tuck 管控 LLM 流量（本地 + 外网）的**内容本身**：检测 → 政策 → 混淆/拦截 → 审计。
CI-144 是地基（身份/审计/防篡改），不是灵魂。灵魂是内容治理。
**判字符串，不判含义**——Tuck 永远不做含义级审查（"这段想法合不合适"）。
检测全部是客观谓词（正则/词典/高熵串），可配置、不掺杂语义裁量。
一旦开始判含义，Tuck 就得调 LLM，而那个调用又得过自己审计——递归。
海关验货看单据和 X 光，不揣摩货物的心思。

### D2: 全量过门 + 分级政策（一道门，门后待遇分级）
```
Anaphase → FlowModus（调度：选 endpoint/模型）
                ↓
           Tuck（唯一门：身份核验 → 检测 → 政策 → 混淆 → 审计 → 转发）
                ├─→ 本地 LLM：检测 + 告警 + 记账（秘密卫生，永不拦截）
                └─→ 外网 API：检测 + 混淆 + 可拦截 + 强审计
```
- 本地流量"免检"结论作废：秘密卫生（API key/路径/个人信息被本地模型缓存/日志）、
  轨迹完整性（推理调用必须入账）、策略一致性（一套规则一个执行点）三条理由成立。
- 拦截权限分级：本地高危可拦（hold）、外网全类可拦（block）。

### D3: 三表 = 三个政策维度（政策矩阵正交化）
| 表 | 本质 | 落点 |
|---|---|---|
| `mapping`（混淆表/黑话） | 可逆打码，出境后 LLM 仍可用 | `pass + redact` |
| `guard`（隐私表） | 凭证类不可逆高危，默认不出境 | `block + alert`（本地降级为 alert） |
| `hold`（危险行为表） | 行为级干预，等人类授权开锁 | `hold + alert`（CAPABILITY-13 HITL 决策队列） |

政策矩阵 = `{action: pass/block/hold} × {transform: none/redact} × {alert}`，
优先级 fail-closed：**block > hold > pass**。全部配置注入，默认值只是兜底。

### D4: 审计链 = 唯一账本（不引入第二账本）
- 每笔调用 2 条记录：`request`（目的地/动作/变换/命中类别/混淆引用）+ `response`（状态/demap_miss）。
- **Vault/WAL 概念不引入**（beta 残留）：append-only JSONL 即账本，同步写 + 异步签名锚定，
  一个文件一个真相源。
- `tuck-audit` 是通用链（seq/ts/payload/prev_hash/hash），payload 由策略层填充——
  策略词汇不污染账本 crate（零行业词汇、极致解耦）。
- 链文件 0600（Unix）；seq 从文件尾恢复（崩溃续写，不用 UUID）；Clock 注入（确定性重放）。

### D5: 混淆态入链 + 映射表驻内存（Rosetta 规则）
- 审计链只存**混淆后内容 + 占位符引用**，映射表本体**绝不入链**——否则混淆自欺，
  审计链变成敏感数据湖。
- 映射表会话级（同实体同会话恒同占位符）、确定性派生（`P_00`…简短省 token）、
  只驻内存；未来落盘必须加密进受限区（v2）。
- demap_miss（占位符无法还原）：原样放行 + 打标计数，不静默不硬拦。
- 映射表/载荷任何日志禁止打印。

### D6: Ed25519 批锚定（外部见证）
- 每 N 条对链头哈希签名（Anchor 记录本身进链，单一链结构）；RFC 8032 确定性签名。
- 验证 = 验最后锚点 + 重放全链；`verify_anchors(pubkey, min_anchors)`——
  **整链重写（重算哈希）可被锚点拒绝**，这是防"日志所有者作恶"的外部见证。
- 密钥缺失 → 降级纯哈希链（按需加载，签名是增强不是门槛）。
- 密钥轮换/前向安全（Bellare-Yee）留 v2（本地单进程威胁模型下 ROI 不足）。

### D7: 旁路焊死（一道门的物理前提）
- Anaphase config 不得再有直连 LLM endpoint——唯一出口 = FlowModus（其下游必经 Tuck）。
- 不焊死，一道门就是纸糊的。此条为架构铁律，Anaphase 侧配置改造为外部依赖。

### D8: SPOF 显式接受
- Tuck down = 全生态停止思考。这是 fail-closed 哲学的清醒选择：
  **网关可用性换审计完整性**。配套：进程自动重启 + 审计链 O_APPEND 崩溃续写。

### D9: trace_id 跨账本关联（轨迹白盒的前提）
- 审计条目带调用方 `trace_id`（Anaphase 确定性派生 `{job_id}#{index}`），
  轨迹视图按 trace_id join Tuck 审计链 + Anaphase ledger = 完整白盒
  （发了什么 prompt（混淆版）、命中什么检测、花了几 token、demap_miss 多少）。

### D10: 身份核验 fail-closed
- 网关 Bearer 认证：未配置密钥 = 拒绝一切；密钥不匹配 = 拒绝。先于内容治理执行。

### D11: 会话令牌（JWT HS256）+ 只读审计查询（2026-09-07 落地）
- 双通道身份：静态 key = 系统级（进程间）；JWT = 会话级（CAPABILITY-13 三模式
  scopes 的天然载体）。`scope` claim 作为不透明标签透传进审计条目，Tuck 永不
  语义解释（判字符串不判含义）。
- 实现零魔法：HS256 直接用 hmac+sha2 手写三段式（header.payload.sig），不引
  jsonwebtoken 重依赖；算法钉死 HS256（无算法混淆面）；常量时间比较；签发确定
  性（同 claims → 同 token，无随机 nonce）。
- `GET /v1/audit`（feature `audit`）：只读查询端点，按 trace_id/kind/action 过滤，
  身份门拦截（fail-closed）。直接读链文件——不触碰内存热路径。WebUI 驾驶舱
  轨迹视图按 trace_id join Tuck 审计链 + Anaphase ledger 的数据源（D9 落地）。

### D12: 旁路焊死装配——网关服务 + L2 凭证注入（2026-09-07 落地）
- `tuck` 二进制新增 feature `gateway`（按需加载）：`TuckConfig.gateway` 段装配
  governance_router 并 serve（复用 `server.host/port`，零新端口字段）。监听、
  上游、凭证、审计路径、规则文件全部注入自 config——零硬编码。
- **L2 凭证物理注入落地**：`GatewayState.upstream_key`——转发上游时**替换**
  Authorization 为上游真实凭证，调用方凭证（Tuck 身份 key / JWT）**永不离开本机**。
  物理事实验证：mock upstream 回显所见 auth = `Bearer sk-upstream-secret`
  （非调用方 key），e2e curl 实证。
- **Anaphase 零代码改动接入**：`reasoning_endpoint` 指向 Tuck 网关
  （`http://127.0.0.1:<port>/v1`）、`reasoning_api_key` = Tuck 身份凭证——
  物理上唯一出口（D7 架构铁律达成）。配置即接线，无旁路代码。

## 3. 备选方案与拒绝理由
| 备选 | 拒绝理由 |
|---|---|
| 本地直连免检 | 秘密卫生/轨迹完整性/策略一致性三条均被破坏 |
| Vault CAS 去重存储 | 审计 JSONL 本身可查可验证；第二账本 = 两个真相源 |
| 每条记录签名 | 密钥进热路径，开销大；批锚定开销≈0 且验证等价 |
| 密钥轮换（前向安全） | 本地单进程威胁模型 ROI 不足；实体增长违背如无必要勿增实体 |
| 响应全量缓冲再检测 | 毁流式体验；token 流已发出拦不住（物理事实），v1 只告警 |
| 含义级审查（Tuck 调 LLM 判内容） | 递归审查无解 + 违背判字符串不判含义 |

## 4. 后果
**正面**:
- Tuck 从"带私有协议的网关"升级为"内容治理海关"——不可替代性成立；
- 本地+外网全量审计 → 轨迹视图获得"思考本身"的数据源；
- 三表政策矩阵物理上可配置、可审计、可回放；
- P4 审计承诺真实兑现（此前是蓝图先行）。

**负面/代价**:
- Tuck 成为最高敏感资产（持映射表 + 全量载荷 + 审计链）——安全性 SPOF 与可用性 SPOF 同时接受；
- 网关工程量大（检测引擎/混淆/流式 demap/审计接入已完成 v1）；
- 旁路焊死依赖 Anaphase 侧配置改造（外部联动）。

**风险与对策**:
- 映射表泄露 → 只驻内存 + 禁止日志 + 未来加密落盘受限区（v2）；
- 检测误报 → 规则全配置可调，客观谓词可复核；
- 整链替换 → 签名锚定拒绝（D6 已验证）。

## 5. 实现要点（与任务映射）
| 决策 | 实现 | 状态 |
|---|---|---|
| D1/D3 | tuck-gateway policy（RuleSet 三表）+ matrix（正交政策） | ✅ T-B2/T-B3 |
| D2 | gov 全链路（检测→政策→redact→转发→demap） | ✅ T-B5 |
| D4/D9 | tuck-audit 通用链 + gateway audit 接入（trace_id） | ✅ T-A1/T-C2 |
| D6 | Ed25519 批锚定 + verify_anchors | ✅ T-A2 |
| D5 | MappingTable 会话级驻内存 + 混淆态入链 | ✅ T-B4/T-C2 |
| D10 | Bearer 认证 fail-closed | ✅ T-C1 |
| D7 | Anaphase 唯一出口 | ⏳ 外部联动（候选 D'-2 范围） |
| D8 | 进程重启 + 崩溃续写 | ✅ 续写已实现；重启编排待部署 |

## 6. 一句话总结
> 普通网关管连接，Tuck 管内容；CI-144 是它的海关标准，
> 内容治理是它的查验本身——判字符串、不判含义，账本防篡改、见证有签名。
