# ledger/ · 三本账之一（**append-only**）

承 phyt-DNA `template/ledger/README.md`，**规则不另立**：

* **只追加，永不改写**。纠正 = 追加一条 `verdict: correction` 的新记录
* `kind` 必填：`task` | `probe` | `scan` | `selftest` | `sim` | `correction`
* **生产指标只算 `kind: task`**（探针/扫描/自检/模拟不计入）

## 本仓（Tuck）为什么需要它

**Tuck 已有验证**（`tools/verify.sh`：workspace 测试 · clippy · **每个 crate 各自可编译（K24）**），
但**跑完什么都不留** —— 于是"我在什么时候验过、当时是什么状态"无法回答。
⇒ 与 adopters 那边同一个理由：**手写的是声明，生成的是证据。**（`KNOWN_ISSUES` 登记规则第 5 条同理）

## 本仓的记录形状（**结构化，不写自由文本** —— 承 P7）

```json
{"ts":"…","gate_id":"verify","verdict":"pass|block","kind":"scan","source":"cli",
 "counts":{"test_groups_ok":12,"clippy_warnings":22,"crates_ok":4,"crates_total":4},
 "env":{"rustc":"…","features":"all","cargo":"…"}}
```

**`env` 由探测得到，绝不手写**（承 P6：手写环境与手写 note 同病 —— 说没起也照写起了）。
