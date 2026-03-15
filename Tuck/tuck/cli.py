#!/usr/bin/env python3
"""
Tuck CLI – Audit tool for Tuck commit history.
"""

import argparse
import heapq
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .kernel import TuckKernel


def format_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def scan_commits(kernel: TuckKernel) -> Iterator[Tuple[float, str, Path]]:
    with os.scandir(kernel.commits) as it:
        for entry in it:
            if entry.name.endswith(".json") and entry.is_file():
                try:
                    mtime = entry.stat().st_mtime
                    commit_id = entry.name[:-5]
                    yield (mtime, commit_id, Path(entry.path))
                except OSError:
                    continue


def get_latest_commits(kernel: TuckKernel, limit: Optional[int], offset: int = 0):
    entries = list(scan_commits(kernel))
    entries.sort(key=lambda x: (-x[0], x[1]))
    if limit:
        return entries[offset:offset+limit]
    return entries[offset:]


def load_commit_metadata(file_path: Path, commit_id: str) -> Optional[Dict[str, Any]]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("id") != commit_id:
            return None
        payload = data.get("payload", {})
        return {
            "id": commit_id,
            "model": payload.get("model", "unknown"),
            "persona": bool(payload.get("persona")),
            "time": format_timestamp(file_path.stat().st_mtime),
        }
    except Exception:
        return None


def collect_commits(kernel: TuckKernel, limit: Optional[int], offset: int):
    latest = get_latest_commits(kernel, limit, offset)
    return [m for m in (load_commit_metadata(p, c) for _, c, p in latest) if m]


def print_table(commits: List[Dict[str, Any]]):
    if not commits:
        print("No commits found.")
        return
    print(f"{'TIME':<20} | {'COMMIT ID':<13} | {'MODEL':<20} | PERSONA")
    print("-" * 70)
    for c in commits:
        print(f"{c['time']:<20} | {c['id'][:12]:<13} | {c['model']:<20} | {'YES' if c['persona'] else 'NO'}")


def main():
    parser = argparse.ArgumentParser(description="Tuck CLI - 时间穿梭控制台")
    parser.add_argument("-l", "--limit", type=int, default=20, help="显示条数")
    parser.add_argument("-o", "--offset", type=int, default=0, help="偏移量")
    parser.add_argument("--json", action="store_true", help="JSON输出")
    parser.add_argument("--vault", default="~/.tuck_vault", help="数据目录")
    args = parser.parse_args()

    try:
        kernel = TuckKernel(args.vault)
    except Exception as e:
        print(f"内核启动失败: {e}", file=sys.stderr)
        sys.exit(1)

    commits = collect_commits(kernel, args.limit, args.offset)
    if args.json:
        json.dump(commits, sys.stdout, indent=2)
    else:
        print_table(commits)


if __name__ == "__main__":
    main()
