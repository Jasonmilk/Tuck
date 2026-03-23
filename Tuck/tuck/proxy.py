"""
Tuck Proxy – Dynamic model routing, secure authentication, and audit logging.

This module provides an OpenAI-compatible gateway that:
  - Dynamically discovers available models from backend services.
  - Authenticates requests via Bearer token.
  - Injects persona system prompts from local JSON files (with caching).
  - Audits all interactions to the Tuck kernel asynchronously (non-blocking).
  - Forwards requests with production-grade concurrency and error handling.
  -[NEW] Integrates modular security engine for prompt sanitization.
"""

import asyncio
import contextvars
import json
import logging
import os
import re
import secrets
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
from tuck.security.engine import security_engine  # 🔥 引入独立的纯粹安全引擎

# ----------------------------------------------------------------------
# Configuration (Pydantic Settings)
# ----------------------------------------------------------------------
class Settings(BaseSettings):
    tuck_backends: str = Field("8016", env="TUCK_BACKENDS")
    tuck_api_key: str = Field("", env="TUCK_API_KEY")
    tuck_scan_interval: int = Field(60, env="TUCK_SCAN_INTERVAL")
    tuck_personas_dir: str = Field("personas", env="TUCK_PERSONAS_DIR")
    tuck_max_connections: int = Field(500, env="TUCK_MAX_CONNECTIONS")
    tuck_probe_timeout: float = Field(2.0, env="TUCK_PROBE_TIMEOUT")
    tuck_forward_timeout: float = Field(120.0, env="TUCK_FORWARD_TIMEOUT")
    tuck_enable_request_id: bool = Field(True, env="TUCK_ENABLE_REQUEST_ID")
    tuck_keepalive_connections: int = Field(100, env="TUCK_KEEPALIVE_CONNECTIONS")
    tuck_probe_concurrency: int = Field(10, env="TUCK_PROBE_CONCURRENCY")
    tuck_persona_cache_size: int = Field(128, env="TUCK_PERSONA_CACHE_SIZE")
    tuck_max_request_size: int = Field(10 * 1024 * 1024, env="TUCK_MAX_REQUEST_SIZE")

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @field_validator("tuck_backends")
    def validate_backends(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("TUCK_BACKENDS cannot be empty")
        parts =[p.strip() for p in v.split(",") if p.strip()]
        if not parts:
            raise ValueError("TUCK_BACKENDS must contain at least one valid backend")
        return v

settings = Settings()

# ----------------------------------------------------------------------
# Logging & Request ID (Fixing the httpx KeyError Crash)
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
# Persona Cache (Original implementation)
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

# ----------------------------------------------------------------------
# Dynamic Router (Original implementation - 主权恢复)
# ----------------------------------------------------------------------
class TuckRouter:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self._lock = asyncio.Lock()
        self.registry: Dict[str, str] = {}
        self.targets: Set[str] = self._parse_backends(settings.tuck_backends)
        self._probe_semaphore = asyncio.Semaphore(settings.tuck_probe_concurrency)
        if not self.targets:
            logger.warning("No valid backends configured.")

    def _parse_backends(self, raw: str) -> Set[str]:
        targets = set()
        for item in (i.strip() for i in raw.split(",") if i.strip()):
            if item.isdigit():
                targets.add(f"http://127.0.0.1:{item}")
            elif "://" in item:
                targets.add(item.rstrip("/"))
            else:
                targets.add(f"http://{item}")
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
                except Exception as e:
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
            logger.info("Sync complete. Models found: %s", list(self.registry.keys()))

    async def get_url(self, model: str) -> Optional[str]:
        async with self._lock:
            return self.registry.get(model)

    async def all_models(self) -> List[Dict[str, str]]:
        async with self._lock:
            return[{"id": m, "object": "model", "owned_by": "tuck"} for m in self.registry]

# ----------------------------------------------------------------------
# Lifespan
# ----------------------------------------------------------------------
background_audit_tasks: Set[asyncio.Task] = set()

@asynccontextmanager
async def lifespan(app: FastAPI):
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

app = FastAPI(title="Tuck Proxy", version="2.0", lifespan=lifespan, docs_url=None, redoc_url=None)
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
            return JSONResponse(status_code=401, content={"error": {"message": "You didn't provide an API key.", "type": "invalid_request_error"}})
        if not secrets.compare_digest(auth_header[7:], api_key):
            return JSONResponse(status_code=401, content={"error": {"message": "Incorrect API key provided.", "type": "invalid_request_error"}})

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
    return JSONResponse(status_code=500, content={"error": {"message": "Tuck internal infrastructure error", "type": "bridge_error", "detail": str(exc) if settings.tuck_api_key else None}})

# ----------------------------------------------------------------------
# Core API Endpoints
# ----------------------------------------------------------------------
@app.get("/health")
async def health(): return {"status": "ok"}

@app.get("/ready")
async def readiness(request: Request):
    router: TuckRouter = request.app.state.router
    if not router.targets: return JSONResponse(status_code=503, content={"status": "no backends configured"})
    if not router.registry: return JSONResponse(status_code=503, content={"status": "no models discovered"})
    return {"status": "ready"}

@app.get("/v1/models")
async def list_models(request: Request):
    router: TuckRouter = request.app.state.router
    return {"object": "list", "data": await router.all_models()}

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    if int(request.headers.get("content-length", 0)) > settings.tuck_max_request_size:
        raise HTTPException(status_code=413, detail="Request entity too large")
    try:
        body = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    model = body.get("model")
    if not model: raise HTTPException(status_code=400, detail="Missing 'model' field")

    router: TuckRouter = request.app.state.router
    backend_url = await router.get_url(model)
    if not backend_url: raise HTTPException(status_code=404, detail=f"Model '{model}' not found on any authorized backend")

    messages = body.get("messages",[])
    is_stream = body.get("stream", False)

    # 🔥 核心安全层介入：遍历 messages 执行独立模块的黑名单拦截与脱敏混淆
    for msg in messages:
        if isinstance(msg.get("content"), str):
            msg["content"] = security_engine.process(msg["content"])

    # --- Persona Injection ---
    persona_name = request.headers.get("X-Tuck-Persona")
    if persona_name:
        if not re.match(r"^[a-zA-Z0-9_\-]+$", persona_name): raise HTTPException(status_code=400, detail="Invalid persona name format")
        personas_base = Path(settings.tuck_personas_dir)
        if not personas_base.is_absolute(): personas_base = Path(__file__).parent / personas_base
        persona_path = personas_base / f"{persona_name}.json"

        persona_data = await persona_cache.get(persona_path)
        if persona_data is None and persona_path.is_file():
            async with aiofiles.open(persona_path, "r", encoding="utf-8") as f:
                persona_data = json.loads(await f.read())
            await persona_cache.set(persona_path, persona_data)

        if persona_data:
            sys_prompt = persona_data.get("system_prompt")
            if sys_prompt and (not messages or messages[0].get("role") != "system"):
                messages.insert(0, {"role": "system", "content": sys_prompt})
            body.update(persona_data.get("params", {}))

    # --- Prepare forwarding headers ---
    hop_by_hop = {"host", "content-length", "connection", "authorization", "proxy-connection", "keep-alive", "te", "trailer", "upgrade"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in hop_by_hop}
    current_req_id = getattr(request.state, "request_id", request_id_var.get())
    if settings.tuck_enable_request_id: headers["X-Request-ID"] = current_req_id
    headers["X-Forwarded-For"] = request.client.host if request.client else "127.0.0.1"

    client: httpx.AsyncClient = request.app.state.client
    backend_req = client.build_request("POST", f"{backend_url}/v1/chat/completions", json=body, headers=headers)

    # 🔥 核心：拦截并提取 AI 回复 (无损保留原有防阻塞写入逻辑)
    try:
        # 非流式处理
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
                except Exception as e:
                    logger.error(f"非流式解析失败，跳过记录: {e}")
            return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))

        # 流式处理
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
                                except Exception:
                                    pass
                        yield f"{chunk}\n"
                    else:
                        yield "\n"
            finally:
                await resp.aclose()
                if full_reply:
                    record_msgs = list(messages)
                    record_msgs.append({"role": "assistant", "content": full_reply})
                    request_id_var.set(current_req_id)
                    try:
                        await asyncio.to_thread(
                            kernel.sync_history, record_msgs, model, metadata={"request_id": current_req_id}
                        )
                        logger.info(f"对话流结束，已永久录入 Tuck，回复长度: {len(full_reply)}")
                    except Exception as e:
                        logger.error(f"流式保存到 Tuck 失败: {e}")

        return StreamingResponse(stream_generator(), status_code=resp.status_code, headers=dict(resp.headers))

    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Backend timeout")
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Backend unreachable")
