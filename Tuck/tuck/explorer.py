"""
Tuck Explorer – Web UI for browsing Tuck commit history.
"""

import asyncio
import contextvars
import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import aiofiles
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .kernel import TuckKernel

# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------

logger = logging.getLogger("tuck.explorer")
logging.basicConfig(level=logging.INFO)
request_id_var = contextvars.ContextVar("request_id", default="-")

# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------

class Settings(BaseSettings):
    tuck_api_key: str = Field("", env="TUCK_API_KEY")
    tuck_vault_dir: str = Field("~/.tuck_vault", env="TUCK_VAULT_DIR")
    max_commits_per_page: int = 50

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
if not settings.tuck_api_key:
    settings.tuck_api_key = secrets.token_urlsafe(32)
    logger.warning(f"自动生成API Key: {settings.tuck_api_key}")

# ----------------------------------------------------------------------
# Kernel
# ----------------------------------------------------------------------

kernel = TuckKernel(settings.tuck_vault_dir)

# ----------------------------------------------------------------------
# App
# ----------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Tuck WebUI 启动")
    yield
    logger.info("Tuck WebUI 关闭")

app = FastAPI(title="Tuck Explorer", lifespan=lifespan, docs_url=None)

# ----------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------

@app.middleware("http")
async def auth(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    key = request.headers.get("X-Tuck-Key")
    if not key or not secrets.compare_digest(key, settings.tuck_api_key):
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    return await call_next(request)

# ----------------------------------------------------------------------
# API
# ----------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/api/commits")
async def list_commits(limit: int = 50, offset: int = 0):
    entries = []
    with os.scandir(kernel.commits) as it:
        for e in it:
            if e.name.endswith(".json") and e.is_file():
                entries.append(e)
    entries.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    paginated = entries[offset:offset+limit]
    res = []
    for e in paginated:
        try:
            async with aiofiles.open(e.path, "r", encoding="utf-8") as f:
                data = json.loads(await f.read())
            res.append({
                "id": data["id"],
                "model": data["payload"].get("model", "unknown"),
                "persona": bool(data["payload"].get("persona")),
                "time": datetime.fromtimestamp(e.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            })
        except Exception:
            continue
    return res

@app.get("/api/commit/{commit_id}")
async def get_commit(commit_id: str):
    path = kernel.commits / f"{commit_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Commit not found")
    try:
        async with aiofiles.open(path, "r", encoding="utf-8") as f:
            return json.loads(await f.read())
    except Exception:
        raise HTTPException(status_code=500, detail="Load failed")

# ----------------------------------------------------------------------
# Web UI
# ----------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def ui():
    return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <title>Tuck | AI时间机</title>
    <style>
        :root { --bg:#0d1117; --card:#161b22; --text:#c9d1d9; --accent:#58a6ff; }
        body { background:var(--bg); color:var(--text); font-family:system-ui; margin:0; height:100vh; display:flex; }
        #sidebar { width:350px; border-right:1px solid #30363d; overflow-y:auto; }
        #content { flex:1; padding:30px; overflow-y:auto; }
        .item { padding:14px; border-bottom:1px solid #30363d; cursor:pointer; }
        .item:hover { background:#21262d; }
        .tag { background:#238636; color:white; padding:2px 6px; border-radius:10px; font-size:10px; }
        pre { white-space:pre-wrap; font-size:12px; }
        .login { position:fixed; inset:0; display:flex; align-items:center; justify-content:center; }
        .login-box { background:var(--card); padding:40px; border-radius:8px; }
        input { background:#0d1117; border:1px solid #30363d; color:white; padding:10px; width:240px; margin:10px 0; border-radius:6px; }
        button { background:var(--accent); color:white; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; }
    </style>
</head>
<body>
<div class="login" id="login">
    <div class="login-box">
        <h3>🔐 Tuck 时间机</h3>
        <input id="key" placeholder="API Key" type="password">
        <button onclick="login()">进入</button>
    </div>
</div>
<div style="display:flex;width:100%;" id="main">
    <div id="sidebar">
        <div style="padding:20px;border-bottom:1px solid #30363d;font-weight:bold;">🕰️ 对话时间线</div>
        <div id="list"></div>
    </div>
    <div id="content">
        <h3>选择记录进行时间穿梭</h3>
    </div>
</div>
<script>
let apiKey = "";
function login(){
    apiKey = document.getElementById("key").value;
    document.getElementById("login").style.display = "none";
    loadList();
}
async function loadList(){
    const r = await fetch("/api/commits",{headers:{"X-Tuck-Key":apiKey}});
    const data = await r.json();
    document.getElementById("list").innerHTML = data.map(c=>`
        <div class="item" onclick="load('${c.id}')">
            <div style="font-size:11px;color:#8b949e;">${c.id.slice(0,12)}</div>
            <div>${c.model}</div>
            <div style="font-size:12px;">${c.persona?'<span class="tag">人格芯片</span>':''} ${c.time}</div>
        </div>
    `).join("");
}
async function load(id){
    const r = await fetch("/api/commit/"+id,{headers:{"X-Tuck-Key":apiKey}});
    const c = await r.json();
    document.getElementById("content").innerHTML = `
        <h3>Commit: ${c.id.slice(0,16)}</h3>
        <p>模型: ${c.payload.model}</p>
        ${c.payload.persona?'<p>✅ 人格芯片已加载</p>':''}
        <h4>对话内容</h4>
        ${c.payload.messages.map(m=>`
            <div style="background:#161b22;padding:12px;border-radius:6px;margin:8px 0;">
                <b>${m.role}:</b> <pre>${m.content}</pre>
            </div>
        `).join("")}
    `;
}
</script>
</body>
</html>
""")

if __name__ == "__main__":
    uvicorn.run("tuck.explorer:app", host="0.0.0.0", port=8000, reload=True)
