"""
Tuck Explorer – 现代、安全的树状对话导航 Web UI
"""

import hashlib
import json
import os
import secrets
from datetime import datetime
from pathlib import Path

import aiofiles
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# 假设你的目录结构中有 kernel.py
from .kernel import TuckKernel

# --- 配置 ---
class Settings(BaseSettings):
    tuck_vault_dir: str = Field("~/.tuck_vault", env="TUCK_VAULT_DIR")
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
kernel = TuckKernel(settings.tuck_vault_dir)

app = FastAPI(title="Tuck Explorer")

# --- 核心安全校验逻辑 ---
def get_stored_hash():
    # 从 vault 目录读取由 CLI 设置的密码哈希
    pass_file = Path(os.path.expanduser(settings.tuck_vault_dir)) / ".web_pass"
    if pass_file.exists():
        return pass_file.read_text().strip()
    return None

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # 允许访问首页和静态资源
    if request.url.path in ["/", "/health"]:
        return await call_next(request)
    
    user_key = request.headers.get("X-Tuck-Key")
    stored_hash = get_stored_hash()

    # 如果还没设置密码，禁止所有 API 访问
    if not stored_hash:
        return JSONResponse(status_code=403, content={"error": "Admin has not set a password via CLI."})

    # 校验哈希
    if not user_key or hashlib.sha256(user_key.encode()).hexdigest() != stored_hash:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    
    return await call_next(request)

# --- API 接口 ---
@app.get("/api/commits")
async def list_commits():
    entries = []
    if not kernel.commits.exists(): return []
    with os.scandir(kernel.commits) as it:
        for e in it:
            if e.name.endswith(".json"): entries.append(e)
    
    entries.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    res = []
    for e in entries:
        try:
            async with aiofiles.open(e.path, "r", encoding="utf-8") as f:
                data = json.loads(await f.read())
            res.append({
                "id": data["id"],
                "model": data["payload"].get("model", "unknown"),
                "persona": bool(data["payload"].get("persona")),
                "time": datetime.fromtimestamp(e.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            })
        except: continue
    return res

@app.get("/api/commit/{commit_id}")
async def get_commit(commit_id: str):
    path = kernel.commits / f"{commit_id}.json"
    if not path.exists(): raise HTTPException(status_code=404)
    async with aiofiles.open(path, "r", encoding="utf-8") as f:
        return json.loads(await f.read())

# --- 前端 UI ---
@app.get("/", response_class=HTMLResponse)
async def ui():
    return HTMLResponse("""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tuck Explorer</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=Fira+Code:wght@400&display=swap');
        body { background: #09090b; color: #e4e4e7; font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'Fira Code', monospace; }
        .glass { background: rgba(18, 18, 21, 0.8); backdrop-filter: blur(10px); border: 1px solid #27272a; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .animate-in { animation: fadeIn 0.4s ease-out forwards; }
    </style>
</head>
<body class="min-h-screen">
    <!-- 登录模块 -->
    <div id="auth-screen" class="fixed inset-0 z-50 flex items-center justify-center bg-[#09090b]">
        <div class="glass p-10 rounded-2xl w-full max-w-sm text-center">
            <h1 class="text-2xl font-bold mb-6 tracking-tight">Tuck Explorer</h1>
            <input id="pwd" type="password" placeholder="输入访问密码" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3 mb-4 focus:outline-none focus:border-blue-500 transition-all text-center">
            <button onclick="login()" class="w-full bg-white text-black font-bold py-3 rounded-lg hover:bg-zinc-200 transition-all">进入系统</button>
        </div>
    </div>

    <!-- 主界面模块 -->
    <div id="main-screen" class="hidden flex h-screen">
        <!-- 左侧树状导航 -->
        <aside class="w-80 border-r border-zinc-900 overflow-y-auto p-6 flex-shrink-0">
            <h2 class="text-zinc-500 text-xs font-bold uppercase tracking-widest mb-8">Timeline</h2>
            <div id="tree" class="relative border-l border-zinc-800 ml-2 pl-6 space-y-8"></div>
        </aside>
        <!-- 右侧内容 -->
        <main class="flex-1 overflow-y-auto p-12 bg-[#0c0c0e]">
            <div id="detail" class="max-w-3xl mx-auto space-y-8">
                <div class="text-zinc-600 text-center mt-20">请选择一个分支查看详情</div>
            </div>
        </main>
    </div>

    <div id="toast" class="fixed bottom-8 left-1/2 -translate-x-1/2 bg-blue-600 text-white px-4 py-2 rounded-full text-xs font-bold opacity-0 transition-opacity pointer-events-none">已复制 ID</div>

    <script>
        let KEY = "";
        function login() {
            KEY = document.getElementById('pwd').value;
            loadList();
        }

        async function loadList() {
            const r = await fetch("/api/commits", { headers: {"X-Tuck-Key": KEY} });
            if (r.ok) {
                document.getElementById('auth-screen').classList.add('hidden');
                document.getElementById('main-screen').classList.remove('hidden');
                const data = await r.json();
                renderTree(data);
            } else {
                alert("访问受限：密码错误或未设置");
            }
        }

        function renderTree(data) {
            const tree = document.getElementById('tree');
            tree.innerHTML = data.map(c => `
                <div class="relative group animate-in">
                    <div class="absolute -left-[32.5px] top-1 w-3 h-3 rounded-full bg-zinc-900 border border-zinc-700 group-hover:border-blue-500 transition-all"></div>
                    <div class="cursor-pointer" onclick="showDetail('${c.id}')">
                        <div class="text-[10px] text-zinc-600 font-mono mb-1">${c.time}</div>
                        <div class="text-sm font-medium text-zinc-300 group-hover:text-white transition-colors">${c.model}</div>
                        <div class="inline-block mt-2 text-[10px] font-mono text-zinc-500 bg-zinc-900 px-2 py-0.5 rounded border border-zinc-800 hover:border-zinc-600" onclick="copy('${c.id}', event)">
                            ${c.id.slice(0,12)}
                        </div>
                    </div>
                </div>
            `).join("");
        }

        async function showDetail(id) {
            const r = await fetch(`/api/commit/${id}`, { headers: {"X-Tuck-Key": KEY} });
            const c = await r.json();
            const detail = document.getElementById('detail');
            detail.innerHTML = `
                <header class="border-b border-zinc-900 pb-8">
                    <h1 class="text-3xl font-bold mb-2">${c.payload.model}</h1>
                    <code class="text-blue-500 text-sm">${c.id}</code>
                </header>
                <div class="space-y-6">
                    ${c.payload.messages.map(m => `
                        <div class="bg-zinc-900/30 border border-zinc-800/50 p-6 rounded-xl">
                            <div class="text-[10px] uppercase tracking-widest text-zinc-500 mb-4 font-bold">${m.role}</div>
                            <pre class="whitespace-pre-wrap text-sm leading-relaxed text-zinc-300 font-mono">${m.content}</pre>
                        </div>
                    `).join("")}
                </div>
            `;
        }

        function copy(text, e) {
            e.stopPropagation();
            navigator.clipboard.writeText(text);
            const t = document.getElementById('toast');
            t.style.opacity = "1";
            setTimeout(() => t.style.opacity = "0", 2000);
        }
        lucide.createIcons();
    </script>
</body>
</html>
""")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
