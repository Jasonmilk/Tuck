#!/usr/bin/env bash
# verify.sh — Tuck 的【一条命令自证】（对标 phyt-DNA 的 tools/ci-local.sh）。
#
# 为什么需要它：README 曾写 `cargo test --workspace`，而 `crates/tuck/Cargo.toml` 是 `default = []`
# 且 `tuck-gateway = optional = true`（按需加载）—— 不带 feature 时**整个 gateway crate 不参与编译**，
# 它的全部测试（policy / hitl / access）**静默跳过**。"不带 feature 的全绿" ≠ "全绿"。
# ⇒ 所以入口必须写死 `--all-features`，否则入口自己就是那个坑。
#
# Usage: bash tools/verify.sh
set -uo pipefail
fail=0
step(){ printf '  %-34s ' "$1"; }

step "workspace tests (--all-features)"
# ★ 分类而非跳过：真跑一遍 `cargo test --workspace --all-features`，由 tools/expected-red.py
#   把「已知在证明缺陷的 9 条」与「真回归」分开判。四判据 + 绿时也打印 KNOWN-LIVE。
#   它比裸 `cargo test` **更严**：名单内条目变绿/没跑/被 #[ignore] 都判红（防「删掉测试就变绿」）。
#   人读说明：crates/tuck-core/tests/EXPECTED-RED.md　机器名单：tools/expected-red.list
if python3 tools/expected-red.py >/tmp/tuck_verify_tests.log 2>&1; then
  tg_ok=$(grep -cE '^test result: ok' /tmp/tuck_expected_red.log 2>/dev/null || echo '?')
  echo "OK  (${tg_ok} 个测试组绿；$(grep -c '^  \[' /tmp/tuck_verify_tests.log) 条 KNOWN-LIVE 已具名)"
  sed -n 's/^/      /p' /tmp/tuck_verify_tests.log
else
  echo "★ RED（详见 /tmp/tuck_verify_tests.log）"; sed -n 's/^/      /p' /tmp/tuck_verify_tests.log; fail=1
fi

# clippy：语义与【本仓自己的标准】一致（PLAN: "clippy 新文件零警告"）——**不把整仓 -D warnings 当门槛**。
# 理由（实测 2026-10-09）：整仓 -D warnings 会把【测试模块里既有的 unused-import】判成 error ⇒ 假红。
# 故本步：① 报告存量警告（具名，进债务）② 只对**真正的 error** 判红 —— 这样它仍然**能红**（不为装饰）。
step "clippy (--all-features)"
cargo clippy --workspace --all-features >/tmp/tuck_verify_clippy.log 2>&1
errs=$(grep -cE '^error' /tmp/tuck_verify_clippy.log || true)
# 只数【真正的 lint 警告行】：cargo 的汇总行形如 "warning: `crate` (lib) generated N warnings"，
# 它不是一条 lint（把它算进去就会像本步第一版那样报"40 条"——一个不可归因的数）。
warns=$(grep -E '^warning: ' /tmp/tuck_verify_clippy.log | grep -vcE 'generated [0-9]+ warning' || true)
if [ "${errs:-0}" -gt 0 ]; then echo "★ RED（${errs} error，详见 /tmp/tuck_verify_clippy.log）"; fail=1
else cw=${warns:-0}; echo "OK  （存量警告 ${cw} 条 —— 见 KNOWN_ISSUES 的债务行，不判红）"; fi

# ★ K24 的回归判据（2026-10-09）：**每个 crate 必须能在 --all-features 下【各自】编译**。
# 为什么这条要单独有：`--all-features` 的语义在【单包】与【工作区】下**不同**（同 K21/D9 的教训）——
# 实测 `cargo build -p tuck-gateway --all-features` 曾报 E0425(cannot find type Arc)，而
# `cargo build --workspace --all-features` **0 error** ⇒ 自证入口（用 workspace）**看不见**它。
# 受害者是**单独构建某个 crate 的人/工具**（IDE 索引、`cargo build -p …`、下游消费者）。
step "每个 crate 各自 --all-features 可编译（K24）"
k24=$(cargo metadata --no-deps --format-version 1 2>/dev/null | python3 -c '
import json,sys
m=json.load(sys.stdin)
print(" ".join(p["name"] for p in m["packages"]))' 2>/dev/null)
bad=""
for pkg in $k24; do
  cargo build -p "$pkg" --all-features >/tmp/tuck_crate_$$.log 2>&1 || bad="$bad $pkg"
done
if [ -n "$bad" ]; then
  echo "★ RED —— 这些 crate 单独编译失败:${bad}"
  echo "      （--all-features 在单包下的语义与工作区不同；详见 KNOWN_ISSUES K24）"; fail=1
else
  echo "OK  （$(echo $k24 | wc -w | tr -d ' ') 个 crate）"
fi

# ★ 修（2026-10-09）：这一步此前叫「gateway crate 参与编译」，却在跑 `--workspace --all-features` ——
#   **名字承诺一件事、命令做另一件事**（声明代替检查的一种），而且 `>/dev/null 2>&1` 让红**没有原因**。
#   实测：它曾报过一次 ★ RED，而同一命令手跑 exit=0 ⇒ 不可归因的红 = 比红更糟（它会教人重跑直到绿）。
#   ⇒ 改成**名实相符**：`gateway` feature 属于 `tuck` 包，故用 `-p tuck --features gateway` 验证
#      "该 feature 真的把 tuck-gateway 拉进编译"；失败时**打印末尾几行**（红必须带原因）。
step "gateway feature 真的把 tuck-gateway 拉进编译"
if out=$(cargo build -p tuck --features gateway 2>&1); then
  echo "OK  （tuck --features gateway）"
else
  echo "★ RED"
  printf '%s\n' "$out" | tail -12 | sed 's/^/    /'
  fail=1
fi

# ★ 把这次自证写进账本（append-only）。承 adopters 的 P6/P7：
#   · 只追加、永不改写 · kind: "scan"（生产指标只算 kind: task）· 计数与环境**结构化**且环境**由探测得到**
#   · **写账失败绝不影响裁决**（打印 WARN，不抛）
rec(){
  [ -d ledger ] || return 0
  local rustc_v cargo_v
  rustc_v=$(rustc --version 2>/dev/null | tr -d '"' | sed 's/^rustc //')
  cargo_v=$(cargo --version 2>/dev/null | awk '{print $2}')
  printf '{"ts":"%s","gate_id":"verify","task":"verify.sh","verdict":"%s","override":false,"source":"cli","event_id":"verify-%s-%s","kind":"scan","counts":{"test_groups_ok":%s,"clippy_warnings":%s},"env":{"rustc":"%s","cargo":"%s","features":"all"},"note":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$(date +%s)" "$$" "${2:-0}" "${3:-0}" "$rustc_v" "$cargo_v" "$4" >> ledger/hits-2026.jsonl
}
echo
if [ "$fail" = 0 ]; then
  rec pass "${tg_ok:-0}" "${cw:-0}" "all green"
  echo "TUCK-VERIFY: 全绿（已写入 ledger/hits-2026.jsonl）"; exit 0
fi
rec block "${tg_ok:-0}" "${cw:-0}" "some step red"
echo "TUCK-VERIFY: 有步骤红" >&2; exit 1
