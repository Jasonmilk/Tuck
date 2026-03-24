import json
import re
from pathlib import Path
from fastapi import HTTPException
import logging

logger = logging.getLogger("tuck.security")

class SecurityEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.base_dir = Path(__file__).parent / rules_dir
        self.blacklist =[]
        self.obfuscation_map = {}
        self.reload_rules()

    def reload_rules(self):
        """加载或重载独立的安全规则文件"""
        try:
            # 加载黑名单
            bl_path = self.base_dir / "blacklist.json"
            if bl_path.exists():
                with open(bl_path, "r", encoding="utf-8") as f:
                    self.blacklist = json.load(f)
            
            # 加载混淆表
            ob_path = self.base_dir / "obfuscation.json"
            if ob_path.exists():
                with open(ob_path, "r", encoding="utf-8") as f:
                    self.obfuscation_map = json.load(f)
                    
            logger.info("Security rules loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load security rules: {e}")

    def process(self, content: str) -> str:
        """执行拦截与混淆"""
        if not isinstance(content, str):
            return content

        # 1. 黑名单截停
        for pattern in self.blacklist:
            if re.search(pattern, content):
                logger.warning(f"Security Alert: Blocked by pattern {pattern}")
                raise HTTPException(
                    status_code=403, 
                    detail="[Tuck Gateway] Security Alert: Prompt contains sensitive information. Request intercepted."
                )
        
        # 2. 语义混淆
        obfuscated = content
        for real_word, fake_word in self.obfuscation_map.items():
            obfuscated = obfuscated.replace(real_word, fake_word)
            
        return obfuscated

# 全局单例引擎
security_engine = SecurityEngine()
