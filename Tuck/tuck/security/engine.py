# /root/Tuck/Tuck/tuck/security/engine.py
import json
import re
from pathlib import Path
from fastapi import HTTPException
import logging

logger = logging.getLogger("tuck.security")

class SecurityEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.base_dir = Path(__file__).parent / rules_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.blacklist =[]
        self.obfuscation_map = {}
        self.reload_rules()

    def reload_rules(self):
        """加载或重载独立的安全规则文件，若不存在则生成初始模板"""
        bl_path = self.base_dir / "blacklist.json"
        ob_path = self.base_dir / "obfuscation.json"

        # 1. 初始化模板 (防止系统首次运行无文件报错)
        if not bl_path.exists():
            with open(bl_path, "w", encoding="utf-8") as f:
                json.dump([r"sk-[a-zA-Z0-9]{32}", r"rm -rf /"], f, ensure_ascii=False, indent=2)
        if not ob_path.exists():
            with open(ob_path, "w", encoding="utf-8") as f:
                json.dump({"项目核心机密": "开源测试项目", "Helix-Mind": "Test-Agent"}, f, ensure_ascii=False, indent=2)

        try:
            with open(bl_path, "r", encoding="utf-8") as f:
                self.blacklist = json.load(f)
            with open(ob_path, "r", encoding="utf-8") as f:
                self.obfuscation_map = json.load(f)
            logger.info("🛡️ Tuck 安全引擎加载完毕: 包含黑名单与迷彩混淆表。")
        except Exception as e:
            logger.error(f"❌ 安全引擎加载失败: {e}")

    def process_request(self, content: str, enable_obfuscation: bool) -> str:
        """执行拦截与迷彩混淆"""
        if not isinstance(content, str): return content

        # 1. 绝对的黑名单截停 (防止密码/Token泄露)
        for pattern in self.blacklist:
            if re.search(pattern, content, re.IGNORECASE):
                logger.warning(f"🚨 安全拦截: 触发黑名单规则 '{pattern}'")
                raise HTTPException(
                    status_code=403, 
                    detail="[Tuck Gateway] Security Alert: Payload contains restricted patterns. Request dropped."
                )
        
        # 2. 语义混淆 (赛博迷彩)
        if enable_obfuscation:
            obfuscated = content
            for real_word, fake_word in self.obfuscation_map.items():
                obfuscated = obfuscated.replace(real_word, fake_word)
            return obfuscated
            
        return content

# 全局单例引擎
security_engine = SecurityEngine()
