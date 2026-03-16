import json
import os
import hashlib
import uvicorn
import datetime
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic_settings import BaseSettings

try:
    from .kernel import TuckKernel
except ImportError:
    from kernel import TuckKernel

# ==========================================
# 1. 配置管理
# ==========================================
class Settings(BaseSettings):
    tuck_vault_dir: str = "~/.tuck_vault"
    web_port: int = 8000
    web_host: str = "0.0.0.0"

settings = Settings()
k = TuckKernel(settings.tuck_vault_dir)
app = FastAPI(title="Tuck Explorer v2.1")

# ==========================================
# 2. 安全中间件 (可选：~/.tuck_vault/.web_pass)
# ==========================================
@app.middleware("http")
async def auth_check(request: Request, call_next):
    public_paths = ["/", "/api/health"]
    if request.url.path in public_paths:
        return await call_next(request)

    pf = Path(os.path.expanduser(settings.tuck_vault_dir)) / ".web_pass"
    if not pf.exists():
        return await call_next(request)

    key = request.headers.get("X-Tuck-Key", "")
    provided_hash = hashlib.sha256(key.encode()).hexdigest()
    stored_hash = pf.read_text().strip()
    
    if provided_hash != stored_hash:
        return JSONResponse(status_code=401, content={"error": "Auth Required"})
    
    return await call_next(request)

# ==========================================
# 3. 核心 API 接口 (均带 _ensure_fresh_index)
# ==========================================

@app.get("/api/health")
async def health():
    return {"status": "ok", "mtime": k._last_index_mtime}

@app.get("/api/topics")
async def get_topics(page: int = 1, page_size: int = 20):
    # 🔥 核心修复：查询前确保索引与硬盘同步
    k._ensure_fresh_index()
    
    topics = list(k._index.get("topics", {}).values())
    # 按最后活跃时间排序
    topics.sort(key=lambda x: x.get("last_seen", 0), reverse=True)
    
    total = len(topics)
    start = (page - 1) * page_size
    return {
        "topics": topics[start : start + page_size],
        "pagination": {
            "page": page, "total": total,
            "total_pages": (total + page_size - 1) // page_size if total > 0 else 1
        }
    }

@app.get("/api/thread/{topic_id}")
async def get_thread(topic_id: str, page: int = 1, page_size: int = 50):
    # 🔥 核心修复：查询前确保索引与硬盘同步
    k._ensure_fresh_index()
    
    node_ids = k._index.get("topic_nodes", {}).get(topic_id, [])
    nodes = []
    
    for nid in node_ids:
        node = k.load_node(nid)
        if not node: continue
        
        content = node["payload"]["content"]
        text = content.get("content", str(content)) if isinstance(content, dict) else str(content)
        
        nodes.append({
            "id": nid,
            "text": text[:100] + ("..." if len(text) > 100 else ""),
            "role": content.get("role", "user") if isinstance(content, dict) else "user",
            "ref_count": node.get("ref_count", 1),
            "timestamp": node.get("timestamp", 0)
        })
    
    nodes.sort(key=lambda x: x["timestamp"], reverse=True)
    total = len(nodes)
    start = (page - 1) * page_size
    
    return {
        "nodes": nodes[start : start + page_size],
        "pagination": { "page": page, "total": total }
    }

@app.get("/api/linear-history/{node_id}")
async def get_history(node_id: str):
    # 追溯历史
    chain = k.get_linear_history(node_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Node not found")
    return chain

@app.get("/api/stats/summary")
async def get_stats():
    # 🔥 核心修复：查询前确保索引与硬盘同步
    k._ensure_fresh_index()
    return k.get_stats_summary()

# ==========================================
# 4. 前端 UI 界面
# ==========================================
@app.get("/", response_class=HTMLResponse)
async def ui():
    html = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>Tuck Explorer v2.1</title>
    <style>
        :root { --bg: #0d1117; --side: #161b22; --border: #30363d; --accent: #58a6ff; --text: #c9d1d9; --muted: #8b949e; }
        * { margin:0; padding:0; box-sizing: border-box; }
        body { font-family: -apple-system, blinkmacsystemfont, "Segoe UI", Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; }
        .app { display: flex; height: 100vh; }
        .panel { display: flex; flex-direction: column; border-right: 1px solid var(--border); background: var(--side); }
        #topic-panel { width: 300px; }
        #node-panel { width: 350px; }
        #main-panel { flex: 1; background: var(--bg); display: flex; flex-direction: column; }
        
        .header { padding: 16px; border-bottom: 1px solid var(--border); font-weight: 600; font-size: 14px; color: var(--accent); display: flex; justify-content: space-between; }
        .content { flex: 1; overflow-y: auto; padding: 10px; }
        
        .card { padding: 12px; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 8px; cursor: pointer; transition: 0.2s; background: #0d1117; }
        .card:hover, .card.active { border-color: var(--accent); background: #1c2128; }
        .card-title { font-size: 13px; font-weight: 500; margin-bottom: 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .card-meta { font-size: 11px; color: var(--muted); display: flex; justify-content: space-between; }
        
        .role-user { color: #58a6ff; }
        .role-assistant { color: #3fb950; }
        .ref-tag { background: #238636; color: white; padding: 1px 6px; border-radius: 10px; font-size: 10px; }

        .chat-view { flex: 1; overflow-y: auto; padding: 30px; }
        .msg { max-width: 85%; margin-bottom: 24px; }
        .msg.user { margin-left: auto; }
        .msg-bubble { padding: 16px; border-radius: 12px; font-size: 14px; line-height: 1.6; white-space: pre-wrap; word-break: break-word; }
        .user .msg-bubble { background: #1f6feb; color: white; border-bottom-right-radius: 2px; }
        .assistant .msg-bubble { background: #21262d; border: 1px solid var(--border); border-bottom-left-radius: 2px; }
        .msg-meta { font-size: 11px; color: var(--muted); margin-bottom: 6px; display: flex; justify-content: space-between; }

        .stats-bar { padding: 15px 30px; background: var(--side); border-top: 1px solid var(--border); display: flex; gap: 40px; }
        .stat-item { display: flex; flex-direction: column; }
        .stat-label { font-size: 11px; color: var(--muted); }
        .stat-val { font-size: 18px; font-weight: 700; color: var(--accent); }

        .loading { text-align: center; padding: 20px; color: var(--muted); font-size: 12px; }
        #login-screen { position: fixed; inset: 0; background: var(--bg); z-index: 100; display: none; align-items: center; justify-content: center; }
        .login-box { background: var(--side); padding: 40px; border-radius: 12px; border: 1px solid var(--border); width: 320px; text-align: center; }
        input { width: 100%; padding: 10px; background: var(--bg); border: 1px solid var(--border); color: white; border-radius: 4px; margin: 20px 0; outline: none; }
    </style>
</head>
<body>
    <div id="login-screen">
        <div class="login-box">
            <h3>🔐 Tuck Vault</h3>
            <input type="password" id="pass" placeholder="输入访问密钥..." onkeydown="if(event.key==='Enter') login()">
            <button onclick="login()" style="width:100%; padding:10px; cursor:pointer; background:var(--accent); border:none; color:white; border-radius:4px;">解锁</button>
        </div>
    </div>

    <div class="app">
        <div class="panel" id="topic-panel">
            <div class="header"><span>对话流</span><span id="topic-total">0</span></div>
            <div class="content" id="topic-list"></div>
        </div>
        <div class="panel" id="node-panel">
            <div class="header"><span>版本节点</span><span id="node-total">0</span></div>
            <div class="content" id="node-list"><div class="loading">请先选择话题</div></div>
        </div>
        <div class="panel" id="main-panel">
            <div class="chat-view" id="chat-view"></div>
            <div class="stats-bar" id="stats-bar"></div>
        </div>
    </div>

    <script>
        let STATE = { key: localStorage.getItem('tuck_key') || '', topic: null, node: null };
        
        async function call(path) {
            const res = await fetch(`/api/${path.replace(/^\//,'')}`, {
                headers: { 'X-Tuck-Key': STATE.key }
            });
            if (res.status === 401) { document.getElementById('login-screen').style.display='flex'; throw 'Auth'; }
            return res.json();
        }

        async function login() {
            STATE.key = document.getElementById('pass').value;
            try { await call('health'); localStorage.setItem('tuck_key', STATE.key); location.reload(); }
            catch { alert('密钥错误'); }
        }

        async function loadTopics() {
            const data = await call('topics');
            document.getElementById('topic-total').innerText = data.pagination.total;
            document.getElementById('topic-list').innerHTML = data.topics.map(t => `
                <div class="card ${STATE.topic === t.topic_id ? 'active' : ''}" onclick="selectTopic('${t.topic_id}')">
                    <div class="card-title">${escape(t.text)}</div>
                    <div class="card-meta"><span>${t.model}</span><span>${t.node_count} nodes</span></div>
                </div>
            `).join('') || '<div class="loading">暂无记录</div>';
        }

        async function selectTopic(id) {
            STATE.topic = id;
            document.querySelectorAll('#topic-list .card').forEach(c => c.classList.remove('active'));
            event.currentTarget.classList.add('active');
            
            const data = await call(`thread/${id}`);
            document.getElementById('node-total').innerText = data.pagination.total;
            document.getElementById('node-list').innerHTML = data.nodes.map(n => `
                <div class="card" onclick="selectNode('${n.id}')">
                    <div class="card-meta"><span class="role-${n.role}">${n.role.toUpperCase()}</span> ${n.ref_count > 1 ? '<span class="ref-tag">Reuse</span>' : ''}</div>
                    <div class="card-title" style="font-weight:400; font-size:12px; margin-top:5px">${escape(n.text)}</div>
                </div>
            `).join('');
        }

        async function selectNode(id) {
            const history = await call(`linear-history/${id}`);
            const view = document.getElementById('chat-view');
            view.innerHTML = history.map(h => {
                const msg = h.payload.content;
                const role = msg.role || 'user';
                const text = typeof msg === 'string' ? msg : (msg.content || '');
                return `
                <div class="msg ${role}">
                    <div class="msg-meta"><span>${role.toUpperCase()}</span><span>${new Date(h.timestamp*1000).toLocaleTimeString()}</span></div>
                    <div class="msg-bubble">${escape(text)}</div>
                </div>`;
            }).join('');
            view.scrollTop = view.scrollHeight;
        }

        async function loadStats() {
            const s = await call('stats/summary');
            document.getElementById('stats-bar').innerHTML = `
                <div class="stat-item"><span class="stat-label">总处理量</span><span class="stat-val">${s.total_msgs}</span></div>
                <div class="stat-item"><span class="stat-label">复用节点</span><span class="stat-val">${s.total_reused_nodes}</span></div>
                <div class="stat-item"><span class="stat-label">复用率</span><span class="stat-val">${(s.overall_reuse_rate*100).toFixed(1)}%</span></div>
                <div class="stat-item"><span class="stat-label">对话流</span><span class="stat-val">${s.topic_count}</span></div>
            `;
        }

        function escape(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
        
        // 每 10 秒自动刷新一次列表和统计
        setInterval(() => { loadTopics(); loadStats(); }, 10000);
        
        loadTopics(); loadStats();
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html)

if __name__ == "__main__":
    uvicorn.run(app, host=settings.web_host, port=settings.web_port)
