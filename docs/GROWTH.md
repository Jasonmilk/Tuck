# Tuck 生长记录（GROWTH）

> **所属方法论**：phyt-DNA v1.0
> **规则**：保留最近 3 次健康快照。超过 3 条时，最旧的移入 `docs/archive/growth/`。历史永不删除。

---

### [2026-09-15] 准入闸门全 8 项 + 语料热加载 + `gov.rs` 解耦（ADR-0005 D9/T9）

**变异类型**：治理能力补齐 + 膨胀控制

- **准入闸门（`ADR-0005` H-1..H-8 全交付）**：白/黑名单同表（`effect`）、
  LLM 三件套能力维度（`llm:egress` / `llm:invoke:<supplier>` / `llm:model:<model>`）、
  审计链扩字段、通知 sink trait（**不内置实现**）、观察模式、配置样例。
  **关键设计：`None` ≠ 空表** —— 未装表 = 闸门不参与；空表 = 拒绝一切。
  混淆两者会让「从没配过 access 的部署」在开启 feature 瞬间全断。
- **H-9 语料热加载**：`RuleSet` 原子替换，**编译失败保留旧规则**（fail-closed 到旧值，不是空）；
  opt-in（无 path 无 watcher）。**顺带订正 D9 本身的术语**：原文写「映射表热加载」有误 ——
  `MappingTable` 是**运行时会话状态**，热替换会毁掉占位符一致性，已发往上游的脱敏文本
  **无法还原**；只有 `RuleSet`（配置数据）该热加载。
- **`gov.rs` 解耦**：1154 → **388 行**。诊断先纠正过一次 —— 曾以为 `governed_chat`
  是 639 行的上帝函数，实际 **337 行**，那 639 把文件末尾 **302 行 inline 测试**算了进去。
  纠正后方案从「拆有状态的 SSE carry」变成「**把测试搬出去**」，更安全也更对。
  最终：`state` / `identity` / `ledger` / `audit_api` / `router` 各成一档。

**验收**：测试 **363 → 410**（每步 A/B 对照，零行为变更）；全 crate 14 模块无一超 400 红线。

### 2026-09-07 真实链路 live 验证 + 凭证治理机制 ✅（ADR-0004 D12 收口）

- **事件**：①Anaphase reasoning_endpoint 真实切到 Tuck 网关（tk-local-gate 身份凭证，
  真实 deepseek key 移入 Tuck config.toml，gitignored）——**live 验证达成**：真实 deepseek
  响应经 Tuck 之门返回，审计链记录 request/response 对（dest=external，hash 链），
  `/v1/audit` 查询可读。②**抓到一个 mock 掩盖的真伤**：workspace reqwest 为
  default-features=false + json/stream——**无 TLS 后端**，http（mock）通、https（真实 LLM）必挂；
  加 rustls-tls 后真实链路才通。③**API key 泄露审计**：发现真实 key 曾进 anaphase-helix
  git 历史（60df6f8 引入，已推送 GitHub）——唯一泄露面；机制修复：Anaphase config.toml/.bak
  untrack（部署配置永不进 git）、Tuck *.jsonl ignore；根治=用户轮换 key（待办）。
- **验证**：live curl——无 key 401 / 带 key 真实 deepseek 响应 / 审计链双记录 / 查询 2 条。
- **指标**：369 passed / 0 failed / 0 warnings（--all-features）。commit fc691d7（rustls）+ b4dc907/9335a7a（凭证治理）。
- **下一步**：用户轮换 deepseek key 后更新 Tuck/config.toml upstream_key；Cellrix 轨迹视图消费 /v1/audit。

### 2026-09-07 内容治理 v1.1 + 零警告专项 ✅（ADR-0004 + D11）

- **事件**：①零警告专项：tuck-core 47 个 warning 全清（Debug 补全 / 缺 doc / unused import / 类型极限比较），
  并修复 --all-features 下 AuditChain 非 Send 隐藏炸弹（signer 改 `Arc<dyn Fn + Send + Sync>`，
  SSE 治理流不再编译挂）。②会话令牌 JWT HS256（零魔法 hmac+sha2 手写，scope claim = CAPABILITY-13
  三模式 scopes 载体，透传进审计）。③只读审计查询 `GET /v1/audit`（trace_id/kind/action 过滤，
  身份门拦截，读链文件不碰热路径）——WebUI 驾驶舱轨迹视图数据源。④VISION v2.1 + SPEC/RNA 对齐：
  消除"不解密载荷 vs 内容治理"表面歧义——帧层（L1）永不碰载荷，内容层（L4）判字符串不判含义；
  DNA 红线未动。
- **关键决策**：双通道身份（静态 key 系统级 / JWT 会话级）；签发确定性（同 claims → 同 token）；
  审计查询直接读链文件（极致解耦，零热路径锁）。
- **指标**：368 passed / 0 failed / 0 warnings（--all-features）。commit 505566a（feat）+ a7d3fe8（零警告）+ 1ff6b60（文档）。
- **下一步**：Cellrix WebUI 驾驶舱轨迹视图按 trace_id join Tuck /v1/audit + Anaphase ledger（白盒可查落地）。
