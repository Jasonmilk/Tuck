#!/usr/bin/env python3
import argparse
import hashlib
import os
import sys
from pathlib import Path

# 兼容包运行
try:
    from .kernel import TuckKernel
except ImportError:
    from kernel import TuckKernel

def main():
    parser = argparse.ArgumentParser(description="Tuck CLI - 管理中心")
    parser.add_argument("--set", nargs=2, metavar=('KEY', 'VALUE'), help="设置配置，例如: --set explorer_password 123456")
    parser.add_argument("-l", "--limit", type=int, default=20)
    parser.add_argument("--vault", default="~/.tuck_vault")
    args = parser.parse_args()

    # 初始化内核
    vault_path = os.path.expanduser(args.vault)
    kernel = TuckKernel(vault_path)

    if args.set:
        key, value = args.set
        if key == "explorer_password":
            # 密码文件存放在 vault 根目录下
            pass_file = Path(vault_path) / ".web_pass"
            hashed = hashlib.sha256(value.encode()).hexdigest()
            pass_file.write_text(hashed)
            print(f"✅ Web UI 访问密码已更新")
            print(f"存储路径: {pass_file}")
            return
        else:
            print(f"❌ 未知配置项: {key}")
            return

    print(f"Tuck Vault 路径: {vault_path}")
    print("提示: 使用 --set explorer_password [你的密码] 来开启 Web 访问")

if __name__ == "__main__":
    main()
