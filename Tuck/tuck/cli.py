#!/usr/bin/env python3
# /root/Tuck/Tuck/tuck/cli.py
import argparse
import hashlib
import os
from pathlib import Path

def update_env(key: str, value: str, env_path: Path):
    """优雅更新或追加 .env 文件配置"""
    lines =[]
    if env_path.exists():
        lines = env_path.read_text().splitlines()
    
    found = False
    with env_path.open("w") as f:
        for line in lines:
            if line.startswith(f"{key}="):
                f.write(f"{key}={value}\n")
                found = True
            else:
                f.write(line + "\n")
        if not found:
            f.write(f"{key}={value}\n")

def main():
    parser = argparse.ArgumentParser(description="Tuck CLI - 流量路由与安全管理中心")
    parser.add_argument("--set", nargs=2, metavar=('KEY', 'VALUE'), help="手动设置底层配置项")
    parser.add_argument("--timeout", type=float, help="设置 Tuck 全局代理超时时间 (应对 R1 慢思考)")
    parser.add_argument("--enable-oneapi", action="store_true", help="开启 One-API 商用超车道")
    parser.add_argument("--disable-oneapi", action="store_true", help="关闭 One-API 通道，全量走本地")
    parser.add_argument("--obfuscate", choices=["none", "commercial", "global"], help="设置语义混淆级别 (防云端审查)")
    parser.add_argument("--vault", default="~/.tuck_vault")
    
    args = parser.parse_args()
    
    # 默认 .env 路径为当前 Tuck 运行目录
    env_path = Path(".env")
    vault_path = Path(os.path.expanduser(args.vault)).resolve()

    if args.set:
        if args.set[0] == "explorer_password":
            vault_path.mkdir(parents=True, exist_ok=True)
            pass_file = vault_path / ".web_pass"
            pass_file.write_text(hashlib.sha256(args.set[1].encode()).hexdigest())
            print(f"✅ Web UI 密码已更新 (存放于 {pass_file})")
        else:
            update_env(args.set[0].upper(), args.set[1], env_path)
            print(f"✅ {args.set[0].upper()} 已硬连接至: {args.set[1]}")

    if args.timeout:
        update_env("TUCK_FORWARD_TIMEOUT", str(args.timeout), env_path)
        print(f"✅ 全局超时时间已拓宽至 {args.timeout} 秒 (重启 Tuck 生效)")

    if args.enable_oneapi:
        update_env("TUCK_ENABLE_ONEAPI", "true", env_path)
        print("🚀 One-API 商用矩阵介入 [已开启]")

    if args.disable_oneapi:
        update_env("TUCK_ENABLE_ONEAPI", "false", env_path)
        print("🛑 One-API 商用矩阵介入 [已关闭]")

    if args.obfuscate:
        update_env("TUCK_OBFUSCATE_MODE", args.obfuscate, env_path)
        print(f"🎭 赛博迷彩 (语义混淆) 模式已设为:[{args.obfuscate.upper()}]")

if __name__ == "__main__":
    main()
