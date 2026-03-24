"""
Tuck Proxy – Dynamic model routing, secure authentication, and audit logging.
* Upgraded with One-API Commercial Fallback, Dynamic Timeouts & Cyber Camouflage *
"""

import asyncio
import contextvars
import json
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import aiofiles
import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from tuck.kernel import TuckKernel

# 尝试挂载高级安全引擎 (赛博迷彩)
try:
    from tuck.security.engine import security_engine
except ImportError:
    security_engine = None

# ----------------------------------------------------------------------
# Configuration (Pydantic Settings)
# ----------------------------------------------------------------------
class Settings(BaseSettings):
    tuck_backends: str = Field("8015,8016,8014", env="TUCK_BACKENDS")
    tuck_api_key: str = Field("", env="TUCK_API_KEY")
    tuck_scan_interval: int = Field(60, env="TUCK_SCAN_INTERVAL")
    tuck_personas_dir: str = Field("personas", env="TUCK_PERSONAS_DIR")
    tuck_max_connections: int = Field(500, env="TUCK_MAX_CONNECTIONS")
    
    # 【物理扩容】：预设 600 秒超时，保障 R1 模型深度思考不断连
    tuck_probe_timeout: float = Field(2.0, env="TUCK_PROBE_TIMEOUT")
    tuck_forward_timeout: float = Field(600.0, env="TUCK_FORWARD_TIMEOUT")
    
    tuck_enable_request_id: bool = Field(True, env="TUCK_ENABLE_REQUEST_ID")
    tuck_keepalive_connections: int = Field(100, env="TUCK_KEEPALIVE_CONNECTIONS")
    tuck_probe_concurrency: int = Field(10, env="TUCK_PROBE_CONCURRENCY")
    tuck_persona_cache_size: int = Field(128, env="TUCK_PERSONA_CACHE_SIZE")
    tuck_max_request_size: int = Field(10 * 1024 * 1024, env="TUCK_MAX_REQUEST_SIZE")
    helix_mind_url: str = Field("", env="HELIX_MIND_URL")

    # --- 🔥 One-API 商业超车道配置 ---
    tuck_enable_oneapi: bool = Field(False, env="TUCK_ENABLE_ONEAPI")
    tuck_oneapi_url: str = Field("", env="TUCK_ONEAPI_URL")
    tuck_oneapi_key: str = Field("", env="TUCK_ONEAPI_KEY")

    # --- 🎭 赛博迷彩开关 (none, commercial, global) ---
    tuck_obfuscate_mode: str = Field("commercial", env="TUCK_OBFUSCATE_MODE")

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @field_validator("tuck_backends")
    def validate_backends(cls, v: str) -> str:
        if not v or not v.strip():
            return "8015,8016,8014"
        return v

settings = Settings()

# ----------------------------------------------------------------------
# Logging & Request ID
# ----------------------------------------------------------------------
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

class RequestIDFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, 'request_id'):
            record.request_id = request_id_var.get()
        return True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] request_id=%(request_id)s %(message)s",
)
logger = logging.getLogger("tuck.proxy")

for handler in logging.getLogger().handlers:
    handler.addFilter(RequestIDFilter())
logging.getLogger("httpx").setLevel(logging.WARNING)

# ----------------------------------------------------------------------
# Kernel Instance
# ----------------------------------------------------------------------
kernel = TuckKernel("~/.tuck_vault")

# ----------------------------------------------------------------------
# Persona Cache & Client
# ----------------------------------------------------------------------
class PersonaCache:
    def __init__(self, maxsize: int = 128):
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._maxsize = maxsize
        self._lock = asyncio.Lock()

    async def get(self, path: Path) -> Optional[Dict[str, Any]]:
        path_str = str(path)
        async with self._lock:
            try:
                mtime = path.stat().st_mtime
            except OSError:
                self._cache.pop(path_str, None)
                return None
            cached = self._cache.get(path_str)
            if cached and cached[0] == mtime:
                return cached[1]
            return None

    async def set(self, path: Path, data: Dict[str, Any]) -> None:
        async with self._lock:
            try:
                mtime = path.stat().st_mtime
            except OSError:
                return
            if len(self._cache) >= self._maxsize:
                self._cache.pop(next(iter(self._cache)))
            self._cache[str(path)] = (mtime, data)

persona_cache = PersonaCache(maxsize=settings.tuck_persona_cache_size)

class PersonaClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.cache: Dict[str, Dict[str, Any]] = {}

    async def get_persona(self, name: str) -> Dict[str, Any]:
        now = time.time()
        cached = self.cache.get(name)
        if cached and now - cached['ts'] < 60:
            return cached['data']
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/v1/persona/{name}")
                if resp.status_code == 200:
                    data = resp.json()
                    self.cache[name] = {'ts': now, 'data': data}
                    return data
                else:
                    logger.warning(f"Helix-Mind 返回 {resp.status_code}，使用空人格")
        except Exception as e:
            logger.error(f"获取人格 {name} 失败: {e}")
        return {"system_prompt": "", "params": {}}

if settings.helix_mind_url:
    persona_client = PersonaClient(settings.helix_mind_url)
    logger.info(f"Helix-Mind 人格服务已挂载: {settings.helix_mind_url}")
else:
    persona_client = None
    logger.info("未配置 HELIX_MIND_URL，使用本地 personas 目录")

# ----------------------------------------------------------------------
# Dynamic Router
# ----------------------------------------------------------------------
class TuckRouter:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self._lock = asyncio.Lock()
        self.registry: Dict[str, str] = {}
        self.targets: Set[str] = self._parse_backends(settings.tuck_backends)
        self._probe_semaphore = asyncio.Semaphore(settings.tuck_probe_concurrency)

    def _parse_backends(self, raw: str) -> Set[str]:
        targets = set()
        for item in (i.strip() for i in raw.split(",") if i.strip()):
            if item.isdigit(): targets.add(f"http://127.0.0.1:{item}")
            elif "://" in item: targets.add(item.rstrip("/"))
            else: targets.add(f"http://{item}")
        return targets

    async def sync(self) -> None:
        new_registry: Dict[str, str] = {}
        async def probe(url: str):
            async with self._probe_semaphore:
                try:
                    resp = await self.client.get(f"{url}/v1/models", timeout=settings.tuck_probe_timeout)
                    if resp.status_code == 200:
                        models = [m["id"] for m in resp.json().get("data",[])]
                        return url, models
                except Exception:
                    pass
                return None

        results = await asyncio.gather(*[probe(u) for u in self.targets])
        for res in results:
            if res:
                url, models = res
                for model in models:
                    new_registry[model] = url

        async with self._lock:
            self.registry = new_registry
            logger.info("Sync complete. Local Models found: %s", list(self.registry.keys()))

    async def get_url(self, model: str) -> Optional[str]:
        async with self._lock:
            return self.registry.get(model)

    async def all_models(self) -> List[Dict[str, str]]:
        async with self._lock:
            return[{"id": m, "object": "model", "owned_by": "tuck"} for m in self.registry]

# ----------------------------------------------------------------------
# Lifespan & FastAPI App
# ----------------------------------------------------------------------
background_audit_tasks: Set[asyncio.Task] = set()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 注入全局 Timeout，保障物理隧道畅通
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.tuck_forward_timeout),
        limits=httpx.Limits(max_connections=settings.tuck_max_connections, max_keepalive_connections=settings.tuck_keepalive_connections),
        follow_redirects=False,
    )
    router = TuckRouter(client)
    app.state.client = client
    app.state.router = router
    await router.sync()

    async def scanner():
        while True:
            await asyncio.sleep(settings.tuck_scan_interval)
            await router.sync()

    scan_task = asyncio.create_task(scanner())
    app.state.scan_task = scan_task
    yield
    if background_audit_tasks:
        await asyncio.gather(*background_audit_tasks, return_exceptions=True)
    scan_task.cancel()
    await client.aclose()

app = FastAPI(title="Tuck Proxy", version="3.0", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ----------------------------------------------------------------------
# Middlewares
# ----------------------------------------------------------------------
@app.middleware("http")
async def authentication(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in["/health", "/ready"]:
        return await call_next(request)

    api_key = settings.tuck_api_key
    if api_key:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"error": {"message": "API key missing.", "type": "invalid_request_error"}})
        if not secrets.compare_digest(auth_header[7:], api_key):
            return JSONResponse(status_code=401, content={"error": {"message": "Invalid API key.", "type": "invalid_request_error"}})

    if settings.tuck_enable_request_id:
        request_id = request.headers.get("X-Request-ID") or secrets.token_hex(16)
        request.state.request_id = request_id
        request_id_var.set(request_id)

    return await call_next(request)

@app.middleware("http")
async def safety_path_sanitizer(request: Request, call_next):
    path = request.scope.get("path", "")
    if path.startswith(("http://", "https://")):
        request.scope["path"] = urlparse(path).path or "/"
    return await call_next(request)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception for %s", request.url)
    return JSONResponse(status_code=500, content={"error": {"message": "Tuck internal error", "detail": str(exc)}})

# ----------------------------------------------------------------------
# Core API Endpoints
# ----------------------------------------------------------------------
@app.get("/health")
async def health(): return {"status": "ok"}

@app.get("/ready")
async def readiness(request: Request):
    router: TuckRouter = request.app.state.router
    if not router.targets: return JSONResponse(status_code=503, content={"status": "no backends"})
    if not router.registry: return JSONResponse(status_code=503, content={"status": "no models"})
    return {"status": "ready"}

@app.get("/v1/models")
async def list_models(request: Request):
    router: TuckRouter = request.app.state.router
    return {"object": "list", "data": await router.all_models()}

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    if int(request.headers.get("content-length", 0)) > settings.tuck_max_request_size:
        raise HTTPException(status_code=413, detail="Payload too large")
    try: body = await request.json()
    except: raise HTTPException(status_code=400, detail="Invalid JSON")

    model = body.get("model")
    messages = body.get("messages",[])
    if not model: raise HTTPException(status_code=400, detail="Missing 'model'")

    # =====================================================================
    # 🚀 流量路由与赛博迷彩 (One-API & Obfuscation)
    # =====================================================================
    use_commercial_intent = request.headers.get("X-Tuck-Commercial", "").lower() == "true"
    route_to_oneapi = use_commercial_intent and settings.tuck_enable_oneapi

    apply_obfuscation = False
    if settings.tuck_obfuscate_mode == "global":
        apply_obfuscation = True
    elif settings.tuck_obfuscate_mode == "commercial" and route_to_oneapi:
        apply_obfuscation = True

    # 🛡️ 执行黑名单拦截与语义替换
    if security_engine:
        for msg in messages:
            if isinstance(msg.get("content"), str):
                try:
                    # 兼容新老版本的安全引擎方法
                    if hasattr(security_engine, "process_request"):
                        msg["content"] = security_engine.process_request(msg["content"], apply_obfuscation)
                    else:
                        msg["content"] = security_engine.process(msg["content"])
                except HTTPException as he:
                    raise he
                except Exception as e:
                    logger.error(f"迷彩处理异常: {e}")

    # 🌐 确定目标地址
    if route_to_oneapi and settings.tuck_oneapi_url:
        logger.info(f"💫 [One-API] 商业通道接管 (Model: {model}) | 迷彩模式: {apply_obfuscation}")
        target_url = settings.tuck_oneapi_url
        if not target_url.endswith('/completions'): target_url = f"{target_url}/v1/chat/completions"
    else:
        router: TuckRouter = request.app.state.router
        backend_url = await router.get_url(model)
        if not backend_url: raise HTTPException(status_code=404, detail=f"Local model '{model}' not found")
        target_url = f"{backend_url}/v1/chat/completions"

    # --- Persona Injection ---
    persona_name = request.headers.get("X-Tuck-Persona")
    sys_prompt = None
    params_override = {}

    if persona_name:
        if persona_client:
            try:
                p_data = await persona_client.get_persona(persona_name)
                sys_prompt = p_data.get("system_prompt")
                params_override = p_data.get("params", {})
            except: pass

        if sys_prompt is None:
            p_base = Path(settings.tuck_personas_dir)
            if not p_base.is_absolute(): p_base = Path(__file__).parent / p_base
            p_path = p_base / f"{persona_name}.json"
            p_data = await persona_cache.get(p_path)
            if p_data is None and p_path.is_file():
                async with aiofiles.open(p_path, "r", encoding="utf-8") as f:
                    p_data = json.loads(await f.read())
                await persona_cache.set(p_path, p_data)
            if p_data:
                sys_prompt = p_data.get("system_prompt")
                params_override = p_data.get("params", {})

        if sys_prompt and (not messages or messages[0].get("role") != "system"):
            messages.insert(0, {"role": "system", "content": sys_prompt})
        if params_override:
            body.update(params_override)

    # --- Headers & Forwarding ---
    hop_by_hop = {"host", "content-length", "connection", "authorization", "proxy-connection", "keep-alive", "te", "trailer", "upgrade"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in hop_by_hop}
    current_req_id = getattr(request.state, "request_id", request_id_var.get())
    if settings.tuck_enable_request_id: headers["X-Request-ID"] = current_req_id
    headers["X-Forwarded-For"] = request.client.host if request.client else "127.0.0.1"
    
    if route_to_oneapi and settings.tuck_oneapi_key:
        headers["Authorization"] = f"Bearer {settings.tuck_oneapi_key}"

    client: httpx.AsyncClient = request.app.state.client
    backend_req = client.build_request("POST", target_url, json=body, headers=headers)

    # --- Sync & Async Response Handling ---
    is_stream = body.get("stream", False)
    try:
        if not is_stream:
            resp = await client.send(backend_req)
            if resp.status_code == 200:
                try:
                    ai_reply = resp.json()["choices"][0]["message"]["content"]
                    record_msgs = list(messages)
                    record_msgs.append({"role": "assistant", "content": ai_reply})
                    asyncio.create_task(asyncio.to_thread(
                        kernel.sync_history, record_msgs, model, metadata={"request_id": current_req_id}
                    ))
                except: pass
            return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))

        resp = await client.send(backend_req, stream=True)

        async def stream_generator():
            full_reply = ""
            try:
                async for chunk in resp.aiter_lines():
                    if chunk:
                        if chunk.startswith("data: "):
                            data_str = chunk[6:]
                            if data_str.strip() != "[DONE]":
                                try:
                                    payload = json.loads(data_str)
                                    content = payload.get("choices", [{}])[0].get("delta", {}).get("content", "")
                                    full_reply += content
                                except: pass
                        yield f"{chunk}\n"
                    else: yield "\n"
            finally:
                await resp.aclose()
                if full_reply:
                    record_msgs = list(messages)
                    record_msgs.append({"role": "assistant", "content": full_reply})
                    try:
                        await asyncio.to_thread(kernel.sync_history, record_msgs, model, metadata={"request_id": current_req_id})
                    except Exception as e:
                        logger.error(f"流式保存到 Tuck Kernel 失败: {e}")

        return StreamingResponse(stream_generator(), status_code=resp.status_code, headers=dict(resp.headers))

    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Backend timeout (600s exceeded or remote down)")
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Backend unreachable")
