#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from .kernel import TuckKernel

def main():
    parser = argparse.ArgumentParser(description="Tuck CLI - 管理中心")
    # 新增 --set 功能
    parser.add_argument("--set", nargs=2, metavar=('KEY', 'VALUE'), help="设置配置项，如: --set explorer_password 123456")
    
    parser.add_argument("-l", "--limit", type=int, default=20)
    parser.add_argument("--vault", default="~/.tuck_vault")
    args = parser.parse_args()

    kernel = TuckKernel(args.vault)

    # 处理密码设置
    if args.set:
        key, value = args.set
        if key == "explorer_password":
            pass_file = Path(os.path.expanduser(args.vault)) / ".web_pass"
            # 使用 SHA-256 哈希存储
            hashed = hashlib.sha256(value.encode()).hexdigest()
            pass_file.write_text(hashed)
            print(f"✅ Web UI 访问密码已更新 (哈希存储于 {pass_file})")
            return
        else:
            print(f"❌ 未知配置项: {key}")
            return

    # --- 原有列表逻辑 (简化版展示) ---
    print(f"Tuck Vault: {args.vault}")
    print("使用 --set explorer_password [PWD] 来设置 Web 登录密码")

if __name__ == "__main__":
    main()
