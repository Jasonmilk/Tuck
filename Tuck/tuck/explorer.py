import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

import aiofiles
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

try:
    from .kernel import TuckKernel
except ImportError:
    from kernel import TuckKernel

class Settings(BaseSettings):
    tuck_vault_dir: str = Field("~/.tuck_vault", env="TUCK_VAULT_DIR")
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
kernel = TuckKernel(settings.tuck_vault_dir)
app = FastAPI()

def get_stored_hash():
    pass_file = Path(os.path.expanduser(settings.tuck_vault_dir)) / ".web_pass"
    if pass_file.exists():
        return pass_file.read_text().strip()
    return None

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path in ["/", "/health"]:
        return await call_next(request)
    user_key = request.headers.get("X-Tuck-Key")
    stored_hash = get_stored_hash()
    if not stored_hash:
        return JSONResponse(status_code=403, content={"error": "Set password first."})
    if not user_key or hashlib.sha256(user_key.encode()).hexdigest() != stored_hash:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    return await call_next(request)

@app.get("/api/commits")
async def list_commits():
    if not kernel.commits.exists(): return []
    entries = [e for e in os.scandir(kernel.commits) if e.name.endswith(".json")]
    entries.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    res = []
    for e in entries:
        try:
            async with aiofiles.open(e.path, "r", encoding="utf-8") as f:
                data = json.loads(await f.read())
            res.append({
                "id": data["id"],
                "model": data["payload"].get("model", "unknown"),
                "time": datetime.fromtimestamp(e.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            })
        except: continue
    return res

@app.get("/api/commit/{commit_id}")
async def get_commit(commit_id: str):
    path = kernel.commits / f"{commit_id}.json"
    async with aiofiles.open(path, "r", encoding="utf-8") as f:
        return json.loads(await f.read())

@app.get("/", response_class=HTMLResponse)
async def ui():
    return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Tuck Explorer</title>
    <style>
        :root {
            --bg: #09090b; --sidebar: #0c0c0e; --border: #27272a;
            --text-main: #e4e4e7; --text-dim: #71717a; --accent: #3b82f6;
        }
        * { box-sizing: border-box; }
        body { 
            margin: 0; background: var(--bg); color: var(--text-main); 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            overflow: hidden; height: 100vh;
        }

        /* 登录屏 */
        #auth-screen {
            position: fixed; inset: 0; z-index: 100; background: var(--bg);
            display: flex; align-items: center; justify-content: center;
        }
        .login-box {
            background: #121214; border: 1px solid var(--border);
            padding: 40px; border-radius: 24px; width: 320px; text-align: center;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
        }
        input {
            width: 100%; background: #000; border: 1px solid var(--border);
            color: white; padding: 12px; border-radius: 8px; margin: 20px 0;
            text-align: center; font-family: monospace; outline: none;
        }
        input:focus { border-color: var(--accent); }
        button {
            width: 100%; background: white; color: black; border: none;
            padding: 12px; border-radius: 8px; font-weight: bold; cursor: pointer;
        }

        /* 主布局 */
        #main-screen { display: flex; height: 100vh; visibility: hidden; }
        
        /* 侧边栏 */
        aside {
            width: 350px; background: var(--sidebar); border-right: 1px solid var(--border);
            display: flex; flex-direction: column; flex-shrink: 0;
        }
        .sidebar-header { padding: 30px; border-bottom: 1px solid var(--border); font-weight: bold; font-size: 20px; }
        
        /* 树状时间轴 */
        #tree {
            flex: 1; overflow-y: auto; padding: 30px 20px 30px 45px;
            position: relative;
        }
        #tree::before {
            content: ''; position: absolute; left: 30px; top: 0; bottom: 0;
            width: 1px; background: var(--border);
        }

        .node { position: relative; margin-bottom: 40px; cursor: pointer; }
        .node-dot {
            position: absolute; left: -20px; top: 5px;
            width: 10px; height: 10px; border-radius: 50%;
            background: #27272a; border: 2px solid var(--bg); z-index: 2;
            transition: 0.3s;
        }
        .node:hover .node-dot { background: var(--accent); box-shadow: 0 0 10px var(--accent); }
        
        .node-time { font-size: 11px; color: var(--text-dim); margin-bottom: 5px; font-family: monospace; }
        .node-model { font-size: 14px; font-weight: 500; color: #d1d1d6; }
        .node-id {
            display: inline-block; margin-top: 8px; font-size: 10px; font-family: monospace;
            background: #18181b; padding: 4px 8px; border-radius: 4px; border: 1px solid var(--border);
            color: var(--text-dim);
        }
        .node-id:hover { border-color: var(--accent); color: var(--accent); }

        /* 内容区 */
        main { flex: 1; overflow-y: auto; background: #050505; padding: 60px; }
        .detail-card { max-w: 800px; margin: 0 auto; }
        .msg {
            margin-bottom: 30px; border-left: 2px solid var(--border);
            padding: 5px 20px;
        }
        .msg-role { font-size: 10px; font-weight: bold; color: var(--accent); text-transform: uppercase; margin-bottom: 10px; }
        .msg-content { font-size: 14px; line-height: 1.6; color: #ccc; white-space: pre-wrap; font-family: monospace; }

        /* Toast提示 */
        #toast {
            position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%);
            background: var(--accent); color: white; padding: 8px 20px; border-radius: 20px;
            font-size: 12px; font-weight: bold; opacity: 0; transition: 0.3s; pointer-events: none;
        }
    </style>
</head>
<body>
    <div id="auth-screen">
        <div class="login-box">
            <div style="font-size: 24px; font-weight: bold;">TUCK.</div>
            <input id="pwd" type="password" placeholder="Access Key">
            <button onclick="login()">进入系统</button>
        </div>
    </div>

    <div id="main-screen">
        <aside>
            <div class="sidebar-header">时间线</div>
            <div id="tree"></div>
        </aside>
        <main>
            <div id="detail-view" class="detail-card">
                <div style="text-align: center; color: var(--text-dim); margin-top: 100px;">
                    请从左侧时间轴选择一个节点进行探索
                </div>
            </div>
        </main>
    </div>

    <div id="toast">已复制到剪贴板</div>

    <script>
        let KEY = "";
        function login() {
            KEY = document.getElementById('pwd').value;
            fetchList();
        }

        async function fetchList() {
            const r = await fetch("/api/commits", { headers: {"X-Tuck-Key": KEY} });
            if (r.ok) {
                document.getElementById('auth-screen').style.display = 'none';
                document.getElementById('main-screen').style.visibility = 'visible';
                const data = await r.json();
                renderTree(data);
            } else { alert("验证失败"); }
        }

        function renderTree(data) {
            const tree = document.getElementById('tree');
            tree.innerHTML = data.map(c => `
                <div class="node" onclick="showDetail('${c.id}')">
                    <div class="node-dot"></div>
                    <div class="node-time">${c.time}</div>
                    <div class="node-model">${c.model}</div>
                    <div class="node-id" onclick="copyId('${c.id}', event)">${c.id.slice(0,14)}</div>
                </div>
            `).join("");
        }

        async function showDetail(id) {
            const r = await fetch(\`/api/commit/\${id}\`, { headers: {"X-Tuck-Key": KEY} });
            const c = await r.json();
            const view = document.getElementById('detail-view');
            view.innerHTML = \`
                <h1 style="font-size: 32px; margin-bottom: 10px;">\${c.payload.model}</h1>
                <div style="font-family: monospace; color: var(--text-dim); margin-bottom: 50px;">ID: \${c.id}</div>
                \${c.payload.messages.map(m => \`
                    <div class="msg">
                        <div class="msg-role">\${m.role}</div>
                        <div class="msg-content">\${m.content}</div>
                    </div>
                \`).join("")}
            \`;
        }

        function copyId(id, e) {
            e.stopPropagation();
            navigator.clipboard.writeText(id);
            const t = document.getElementById('toast');
            t.style.opacity = "1";
            setTimeout(() => t.style.opacity = "0", 2000);
        }
    </script>
</body>
</html>
""")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
