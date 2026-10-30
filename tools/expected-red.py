#!/usr/bin/env python3
"""expected-red.py — 让「预期红」既不隐藏、也不能被悄悄删掉。

## 它判什么（四判据，缺一条就会退化成「删掉测试就变绿」）

| # | 情形 | 处置 |
|---|---|---|
| R1 | 出现**名单外**的失败 | RED（真回归） |
| R2 | 名单内某条**变绿**（`ok`） | RED：修复与「从名单移除」必须**同一提交**；且须触碰它记录的根因文件（否则是改测试而非改代码） |
| R3 | 名单内某条**没跑**（文件被删 / 改目标 / 根本没跑到） | RED：`ITEM MISSING` |
| R4 | 名单内某条被 `#[ignore]` | RED：`IGNORED`（"禁 `#[ignore]`" 由约定变成机械） |
| R5 | 编译失败 / 一条 test 行都没读到 | RED（fail-closed；不是"没有失败"） |

**R3/R4 是本工具存在的理由**：只判 R1+R2，`rm financial_hitl_forensic.rs`
⇒ 0 失败、无名单外失败 ⇒ 绿，而缺陷一个没修。这与 `repo_of` 同名覆盖同形：
**目标消失了，判据静默失效**。

## 两种 kind（不许混）

- `forensic` —— **取证红**：缺陷在，修了就消失。清单**只许缩短**。
- `caliber`  —— **口径红**：判据比的是一个没有所有者的默认值/阈值，要的是**裁决**，不是修。
  ⇒ 对口径红"只许缩短"是错的（缩短 = 偷偷接受现状）。跨仓实例：anaphase K32 那 2 条。

## 绿也要说话（否则它就是抑制器）

每次运行（**含全绿**）都打印 `KNOWN-LIVE: N` 并逐条列根因行。
"431 绿 + 5 缺陷生效"= 不知道的绿；带 KNOWN-LIVE 的绿 = 知道的绿。

## 调用者（§3.10）

`tools/verify.sh` 的 "workspace tests" 步（每次本地自证 + 每次 push/PR 的 CI gate）。
它不自己跑测试就不成立：**本工具唯一的作用是给真实那一跑做分类**。

Usage: python3 tools/expected-red.py [--from-log FILE] [--selftest]
       --from-log 回放一份已捕获的 cargo 输出（只为造负样本，正常路径不用）
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIST = os.path.join(ROOT, "tools", "expected-red.list")
TEST_LINE = re.compile(r"^test ([\w:]+) \.\.\. (ok|FAILED|ignored)")


def load_list(path):
    items = []
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = [p.strip() for p in line.split("\t")]
            if len(parts) != 3:
                raise SystemExit(f"名单格式必须是 3 列（kind/测试名/根因）: {line!r}")
            kind, name, root_cause = parts
            if kind not in ("forensic", "caliber"):
                raise SystemExit(f"kind 只能是 forensic|caliber: {line!r}")
            items.append((kind, name, root_cause))
    return items


def parse(log):
    states = {}
    for line in log.splitlines():
        m = TEST_LINE.match(line)
        if m:
            states.setdefault(m.group(1), []).append(m.group(2))
    return states


def touched_files():
    """本次改动的文件：工作区 vs HEAD，加上 HEAD 这一个提交。"""
    out = set()
    for rng in (["diff", "--name-only", "HEAD"], ["diff", "--name-only", "HEAD~1", "HEAD"]):
        try:
            r = subprocess.run(["git", "-C", ROOT] + rng, capture_output=True, text=True)
        except OSError:
            continue
        if r.returncode == 0:
            out |= {l.strip() for l in r.stdout.splitlines() if l.strip()}
    return out


def judge(log, items, touched):
    states = parse(log)
    problems = []

    if not states:
        hint = "编译失败或没跑到任何测试" if "error" in log else "输出里一条 test 行都没有"
        problems.append(f"DEAD：{hint} ⇒ 不是「没有失败」，是没读到（fail-closed）")
        return problems, states

    listed = {name for _, name, _ in items}

    # R3 / R4 / R2
    for kind, name, root_cause in items:
        st = states.get(name)
        if st is None:
            problems.append(
                f"ITEM MISSING（{kind}）：{name} 一条都没跑 —— 文件被删 / 目标被改 / 根本没进这次跑。"
                f"根因行仍是 {root_cause}，缺陷没有消失，只是判据不见了"
            )
        elif "ignored" in st:
            problems.append(f"IGNORED（{kind}）：{name} 被 #[ignore] 掉了 —— 那是关掉判据，不是修好缺陷")
        elif "FAILED" not in st:
            msg = f"变绿但未从名单移除（{kind}）：{name}"
            rc_file = root_cause.split(":")[0]
            if rc_file not in touched:
                msg += (
                    f"；且本次改动没碰根因文件 {rc_file} ⇒ 疑似【改测试而不是改代码】。"
                    "转绿必须与「删掉名单条目」在同一提交，且该提交要触碰根因文件"
                )
            problems.append(msg)

    # R1
    for name, st in sorted(states.items()):
        if "FAILED" in st and name not in listed:
            problems.append(f"名单外失败：{name} —— 这是真回归，不是预期红")

    return problems, states


def report(items, states, problems):
    live = [i for i in items if states.get(i[1]) and "FAILED" in states[i[1]]]
    kinds = {}
    for kind, _, _ in live:
        kinds[kind] = kinds.get(kind, 0) + 1
    print(f"KNOWN-LIVE: {len(live)}" + (f"  ({', '.join(f'{k}={v}' for k, v in sorted(kinds.items()))})" if live else ""))
    for kind, name, root_cause in live:
        print(f"  [{kind}] {name}  <- {root_cause}")
    for p in problems:
        print(f"★ RED {p}")
    return 0 if not problems else 1


def selftest():
    items = [
        ("forensic", "a_must_fail", "src/a.rs:1"),
        ("caliber", "b_must_fail", "src/b.rs:2"),
    ]
    cases = [
        ("正常（两条都红）", "test a_must_fail ... FAILED\ntest b_must_fail ... FAILED\n", 0),
        ("R1 名单外失败", "test a_must_fail ... FAILED\ntest b_must_fail ... FAILED\ntest rogue ... FAILED\n", 1),
        ("R2 名单内变绿", "test a_must_fail ... ok\ntest b_must_fail ... FAILED\n", 1),
        ("R3 条目没跑", "test b_must_fail ... FAILED\n", 1),
        ("R4 被 ignore", "test a_must_fail ... ignored\ntest b_must_fail ... FAILED\n", 1),
        ("R5 一条没读到", "error[E0432]: unresolved import\n", 1),
        # 反样本的反样本：必须证明「读到空的判据」不会给出绿
        ("R5b 空输出", "", 1),
    ]
    ok = 0
    for label, log, want in cases:
        problems, states = judge(log, items, touched=set())
        rc = 0 if not problems else 1
        mark = "PASS" if rc == want else "FAIL"
        ok += rc == want
        print(f"  {mark} {label} => rc={rc} want={want}")
    # 绿时也必须打印 KNOWN-LIVE
    problems, states = judge("test a_must_fail ... FAILED\ntest b_must_fail ... FAILED\n", items, set())
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        report(items, states, problems)
    out = buf.getvalue()
    known = "KNOWN-LIVE: 2" in out and "src/a.rs:1" in out
    print(f"  {'PASS' if known else 'FAIL'} 绿时打印 KNOWN-LIVE => {known}")
    ok += known
    total = len(cases) + 1
    print(f"selftest {ok}/{total}")
    return 0 if ok == total else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()

    items = load_list(LIST)
    if items is None:
        print(f"★ RED 名单不存在：{LIST}（那等于「预期红」这个概念被删掉了）")
        return 1
    if not items:
        print("★ RED 名单为空而本工具仍在 gate 里 —— 要么删掉本工具，要么补回条目")
        return 1

    if "--from-log" in sys.argv:
        path = sys.argv[sys.argv.index("--from-log") + 1]
        with open(path, encoding="utf-8") as fh:
            log = fh.read()
    else:
        r = subprocess.run(
            ["cargo", "test", "--workspace", "--all-features", "--no-fail-fast"],
            cwd=ROOT, capture_output=True, text=True,
        )
        log = r.stdout + r.stderr
        with open("/tmp/tuck_expected_red.log", "w", encoding="utf-8") as fh:
            fh.write(log)

    problems, states = judge(log, items, touched_files())
    return report(items, states, problems)


if __name__ == "__main__":
    sys.exit(main())
