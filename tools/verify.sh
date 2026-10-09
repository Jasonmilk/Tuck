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
if cargo test --workspace --all-features 2>&1 | tail -40 | grep -qE '^test result: FAILED'; then
  echo "★ RED"; fail=1
elif cargo test --workspace --all-features >/tmp/tuck_verify_tests.log 2>&1; then
  echo "OK  ($(grep -cE '^test result: ok' /tmp/tuck_verify_tests.log) 个测试组)"
else
  echo "★ RED（详见 /tmp/tuck_verify_tests.log）"; fail=1
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
else echo "OK  （存量警告 ${warns} 条 —— 见 KNOWN_ISSUES 的债务行，不判红）"; fi

step "gateway crate realmente 参与编译"
if cargo build --workspace --all-features >/dev/null 2>&1; then echo "OK"; else echo "★ RED"; fail=1; fi

echo
if [ "$fail" = 0 ]; then echo "TUCK-VERIFY: 全绿"; exit 0; fi
echo "TUCK-VERIFY: 有步骤红" >&2; exit 1
