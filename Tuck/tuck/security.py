# import re
# from fastapi import HTTPException

# 1. 基因锁脱敏黑名单 (触发即截停)
# BLACKLIST_PATTERNS = [
#     r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", # 真实IP正则
#     r"(?i)password\s*=\s*['\"]?[a-zA-Z0-9@#$%^&+=]{8,}['\"]?", # 密码正则
#     r"sk-[a-zA-Z0-9]{32,}" # API Key 泄漏防御
# ]

# 2. 语义混淆映射表 (防止特征码被上游模型平台审查，用户可自定义)
# OBFUSCATION_MAP = {
#     "rust_unsafe_block_feature_123": "[LANG_FEAT_A]",
#     "company_internal_project_x": "[PROJECT_ALPHA]"
# }

# def sanitize_and_obfuscate(content: str) -> str:
#     """对流经 Tuck 的 prompt 进行安全检查和混淆"""
#     if not isinstance(content, str):
#         return content

#     # 步骤一：黑名单检查 (截停)
#     for pattern in BLACKLIST_PATTERNS:
#         if re.search(pattern, content):
#             raise HTTPException(
#                 status_code=403, 
#                 detail="[Tuck Gateway] Security Alert: Prompt contains sensitive information (IP/Password/Key). Request intercepted. Please rewrite."
#             )
    
    # 步骤二：映射表混淆 (替换)
#     obfuscated_prompt = content
#     for real_word, fake_word in OBFUSCATION_MAP.items():
#         obfuscated_prompt = obfuscated_prompt.replace(real_word, fake_word)
        
#     return obfuscated_prompt
