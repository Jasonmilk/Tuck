"""
Tuck Proxy – Dynamic model routing, secure authentication, and audit logging.

This module provides an OpenAI-compatible gateway that:
  - Dynamically discovers available models from backend services.
  - Authenticates requests via Bearer token.
  - Injects persona system prompts from local JSON files (with caching).
  - Audits all interactions to the Tuck kernel asynchronously (non-blocking).
  - Forwards requests with production-grade concurrency and error handling.
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
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from tuck.kernel import TuckKernel

# ----------------------------------------------------------------------
# Configuration (Pydantic Settings) – supports .env and env vars
# ----------------------------------------------------------------------

class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    All timeouts are in seconds.
    """
    # Comma-separated list of backend URLs or ports.
    # Examples: "8016,8020" or "http://10.0.0.1:8080,https://model.example.com"
    tuck_backends: str = Field("8016", env="TUCK_BACKENDS")

    # API key for authentication (if empty, auth is disabled – not recommended)
    tuck_api_key: str = Field("", env="TUCK_API_KEY")

    # Interval between backend health scans (seconds)
    tuck_scan_interval: int = Field(60, env="TUCK_SCAN_INTERVAL")

    # Base directory for persona JSON files (supports absolute or relative path)
    tuck_personas_dir: str = Field("personas", env="TUCK_PERSONAS_DIR")

    # Maximum number of concurrent connections to backends
    tuck_max_connections: int = Field(500, env="TUCK_MAX_CONNECTIONS")

    # Timeout for backend model discovery probes (seconds)
    tuck_probe_timeout: float = Field(2.0, env="TUCK_PROBE_TIMEOUT")

    # Total timeout for forwarded requests (seconds)
    tuck_forward_timeout: float = Field(120.0, env="TUCK_FORWARD_TIMEOUT")

    # Enable request ID tracking (adds X-Request-ID header if missing)
    tuck_enable_request_id: bool = Field(True, env="TUCK_ENABLE_REQUEST_ID")

    # Number of keep-alive connections to maintain
    tuck_keepalive_connections: int = Field(100, env="TUCK_KEEPALIVE_CONNECTIONS")

    # Maximum number of concurrent backend probes during sync (to avoid overwhelming backends)
    tuck_probe_concurrency: int = Field(10, env="TUCK_PROBE_CONCURRENCY")

    # Maximum size of persona cache (number of files)
    tuck_persona_cache_size: int = Field(128, env="TUCK_PERSONA_CACHE_SIZE")

    # Maximum request body size in bytes (default 10MB)
    tuck_max_request_size: int = Field(10 * 1024 * 1024, env="TUCK_MAX_REQUEST_SIZE")

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @field_validator("tuck_backends")
    def validate_backends(cls, v: str) -> str:
        """Ensure that after parsing, at least one backend remains."""
        if not v or not v.strip():
            raise ValueError("TUCK_BACKENDS cannot be empty")
        parts = [p.strip() for p in v.split(",") if p.strip()]
        if not parts:
            raise ValueError("TUCK_BACKENDS must contain at least one valid backend")
        return v


settings = Settings()

# ----------------------------------------------------------------------
# Logging & Request ID (using contextvars for async safety)
# ----------------------------------------------------------------------

logger = logging.getLogger("tuck.proxy")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] request_id=%(request_id)s %(message)s",
)

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

class RequestIDFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id_var.get()
        return True

logger.addFilter(RequestIDFilter())

# ----------------------------------------------------------------------
# Kernel Instance (shared)
# ----------------------------------------------------------------------

kernel = TuckKernel()

# ----------------------------------------------------------------------
# Persona Cache (thread-safe, with mtime invalidation)
# ----------------------------------------------------------------------

class PersonaCache:
    """
    Simple in-memory cache for persona JSON files.
    Entries expire when the underlying file modification time changes.
    Thread-safe for async use with asyncio.Lock.
    """
    def __init__(self, maxsize: int = 128):
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}  # path_str -> (mtime, data)
        self._maxsize = maxsize
        self._lock = asyncio.Lock()

    async def get(self, path: Path) -> Optional[Dict[str, Any]]:
        """Return cached persona data if file hasn't changed, else None."""
        path_str = str(path)
        async with self._lock:
            try:
                mtime = path.stat().st_mtime
            except OSError:
                # File not accessible, remove from cache if present
                self._cache.pop(path_str, None)
                return None

            cached = self._cache.get(path_str)
            if cached and cached[0] == mtime:
                return cached[1]

            # Not in cache or stale
            return None

    async def set(self, path: Path, data: Dict[str, Any]) -> None:
        """Store persona data with current mtime."""
        async with self._lock:
            try:
                mtime = path.stat().st_mtime
            except OSError:
                return  # cannot stat, skip caching

            # If cache is full, evict oldest (simple FIFO)
            if len(self._cache) >= self._maxsize:
                # Remove first item (Python 3.7+ dict preserves insertion order)
                self._cache.pop(next(iter(self._cache)))

            self._cache[str(path)] = (mtime, data)


persona_cache = PersonaCache(maxsize=settings.tuck_persona_cache_size)

# ----------------------------------------------------------------------
# Dynamic Router
# ----------------------------------------------------------------------

class TuckRouter:
    """
    Dynamic router that maps model names to backend URLs.
    Periodically probes backends to update the registry.
    """

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self._lock = asyncio.Lock()
        self.registry: Dict[str, str] = {}  # model -> backend URL
        self.targets: Set[str] = self._parse_backends(settings.tuck_backends)
        self._probe_semaphore = asyncio.Semaphore(settings.tuck_probe_concurrency)

        if not self.targets:
            logger.warning("No valid backends configured. Proxy will not route any models.")

    def _parse_backends(self, raw: str) -> Set[str]:
        """
        Parse a comma-separated list of backends into normalized URLs.
        Supports:
          - Port numbers (e.g., "8016" → "http://127.0.0.1:8016")
          - Full URLs (e.g., "https://model.example.com")
        """
        targets = set()
        for item in (i.strip() for i in raw.split(",") if i.strip()):
            if item.isdigit():
                # Assume localhost with that port
                targets.add(f"http://127.0.0.1:{item}")
            elif "://" in item:
                # Full URL, keep as is
                targets.add(item.rstrip("/"))
            else:
                # Possibly host:port without scheme, assume http
                targets.add(f"http://{item}")
        return targets

    async def sync(self) -> None:
        """
        Probe all backends to update the model registry, with concurrency limit.
        """
        new_registry: Dict[str, str] = {}

        async def probe(url: str):
            async with self._probe_semaphore:
                try:
                    resp = await self.client.get(
                        f"{url}/v1/models",
                        timeout=settings.tuck_probe_timeout,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        models = [m["id"] for m in data.get("data", [])]
                        return url, models
                except Exception as e:
                    logger.debug("Probe failed for %s: %s", url, e)
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
            return [{"id": m, "object": "model", "owned_by": "tuck"} for m in self.registry]

# ----------------------------------------------------------------------
# Lifespan & Background Tasks
# ----------------------------------------------------------------------

# Global set to track background audit tasks for graceful shutdown
background_audit_tasks: Set[asyncio.Task] = set()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.tuck_forward_timeout),
        limits=httpx.Limits(
            max_connections=settings.tuck_max_connections,
            max_keepalive_connections=settings.tuck_keepalive_connections,
        ),
        follow_redirects=False,
    )
    router = TuckRouter(client)
    app.state.client = client
    app.state.router = router

    # Initial sync
    await router.sync()

    # Background scanner
    async def scanner():
        while True:
            await asyncio.sleep(settings.tuck_scan_interval)
            await router.sync()

    scan_task = asyncio.create_task(scanner())
    app.state.scan_task = scan_task

    yield

    # Shutdown: wait for all background audit tasks to complete
    if background_audit_tasks:
        logger.info(f"Waiting for {len(background_audit_tasks)} audit tasks to finalize...")
        await asyncio.gather(*background_audit_tasks, return_exceptions=True)

    # Cancel scanner and close client
    scan_task.cancel()
    await client.aclose()

# ----------------------------------------------------------------------
# FastAPI App
# ----------------------------------------------------------------------

app = FastAPI(
    title="Tuck Proxy",
    version="2.0",
    lifespan=lifespan,
    docs_url=None,  # Disable docs in production
    redoc_url=None,
)

# CORS – must be first middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------------------------
# Authentication & Request ID Middleware
# ----------------------------------------------------------------------

@app.middleware("http")
async def authentication(request: Request, call_next):
    """Authenticate requests using Bearer token unless auth is disabled."""
    # Always allow OPTIONS for CORS preflight
    if request.method == "OPTIONS":
        return await call_next(request)

    # Optional: allow unauthenticated health checks
    if request.url.path in ["/health", "/ready"]:
        return await call_next(request)

    api_key = settings.tuck_api_key
    if api_key:  # auth enabled
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={
                    "error": {
                        "message": "You didn't provide an API key.",
                        "type": "invalid_request_error",
                    }
                },
            )
        token = auth_header[7:]
        if not secrets.compare_digest(token, api_key):
            return JSONResponse(
                status_code=401,
                content={
                    "error": {
                        "message": "Incorrect API key provided.",
                        "type": "invalid_request_error",
                    }
                },
            )

    # Set request ID for logging
    if settings.tuck_enable_request_id:
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = secrets.token_hex(16)
        request.state.request_id = request_id
        request_id_var.set(request_id)

    return await call_next(request)


@app.middleware("http")
async def safety_path_sanitizer(request: Request, call_next):
    """
    Prevent SSRF attacks that try to use absolute paths like 'http://evil.com'.
    FastAPI normalizes the path, but we add an extra layer.
    """
    path = request.scope.get("path", "")
    if path.startswith(("http://", "https://")):
        # Replace with just the path part
        parsed = urlparse(path)
        request.scope["path"] = parsed.path or "/"
    return await call_next(request)


# ----------------------------------------------------------------------
# Exception Handlers
# ----------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Prevent crash, return consistent JSON error."""
    logger.exception("Unhandled exception for %s", request.url)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "message": "Tuck internal infrastructure error",
                "type": "bridge_error",
                "detail": str(exc) if settings.tuck_api_key else None,
            }
        },
    )


# ----------------------------------------------------------------------
# Health & Readiness Endpoints
# ----------------------------------------------------------------------

@app.get("/health")
async def health():
    """Simple health check (always OK if app is running)."""
    return {"status": "ok"}


@app.get("/ready")
async def readiness(request: Request):
    """Readiness probe: checks if router has at least one backend."""
    router: TuckRouter = request.app.state.router
    if not router.targets:
        return JSONResponse(status_code=503, content={"status": "no backends configured"})
    if not router.registry:
        return JSONResponse(status_code=503, content={"status": "no models discovered"})
    return {"status": "ready"}


# ----------------------------------------------------------------------
# Core API Endpoints
# ----------------------------------------------------------------------

@app.get("/v1/models")
async def list_models(request: Request):
    """Return list of discovered models."""
    router: TuckRouter = request.app.state.router
    return {"object": "list", "data": await router.all_models()}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Main proxy endpoint: forwards request to appropriate backend after:
      - Model lookup
      - Optional persona injection (with caching)
      - Asynchronous audit logging to Tuck kernel
    """
    # --- Request size limit (prevent OOM) ---
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.tuck_max_request_size:
        raise HTTPException(status_code=413, detail="Request entity too large")

    # Parse request body
    try:
        body = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    model = body.get("model")
    if not model:
        raise HTTPException(status_code=400, detail="Missing 'model' field")

    # Lookup backend
    router: TuckRouter = request.app.state.router
    backend_url = await router.get_url(model)
    if not backend_url:
        raise HTTPException(
            status_code=404,
            detail=f"Model '{model}' not found on any authorized backend",
        )

    # Prepare messages (may be mutated by persona)
    messages = body.get("messages", [])
    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="'messages' must be an array")

    # --- Persona Injection (safe, cached) ---
    persona_name = request.headers.get("X-Tuck-Persona")
    persona_data = None
    if persona_name:
        # Strict validation: alphanumeric + underscore + hyphen only
        if not re.match(r"^[a-zA-Z0-9_\-]+$", persona_name):
            logger.warning("Invalid persona name rejected: %s", persona_name)
            raise HTTPException(status_code=400, detail="Invalid persona name format")

        # Resolve personas directory (support absolute or relative)
        personas_base = Path(settings.tuck_personas_dir)
        if not personas_base.is_absolute():
            personas_base = Path(__file__).parent / personas_base

        persona_path = personas_base / f"{persona_name}.json"

        # Try cache first
        persona_data = await persona_cache.get(persona_path)
        if persona_data is None:
            # Cache miss, load from disk
            if persona_path.is_file():
                try:
                    async with aiofiles.open(persona_path, "r", encoding="utf-8") as f:
                        content = await f.read()
                    persona_data = json.loads(content)
                    # Store in cache
                    await persona_cache.set(persona_path, persona_data)
                except Exception as e:
                    # Log only relative path to avoid leaking absolute paths
                    rel_path = persona_path.relative_to(personas_base) if personas_base in persona_path.parents else persona_path.name
                    logger.error("Failed to load persona %s: %s", rel_path, e)
                    raise HTTPException(status_code=500, detail="Persona loading failed")
            else:
                # Log only relative path
                rel_path = persona_path.relative_to(personas_base) if personas_base in persona_path.parents else persona_path.name
                logger.warning("Persona file not found: %s", rel_path)

        if persona_data:
            # Inject system prompt if first message is not system
            system_prompt = persona_data.get("system_prompt")
            if system_prompt and (not messages or messages[0].get("role") != "system"):
                messages.insert(0, {"role": "system", "content": system_prompt})
            # Merge additional parameters (e.g., temperature, top_p)
            params = persona_data.get("params", {})
            body.update(params)

    # --- Asynchronous audit to Tuck kernel (non-blocking) ---
    # Run kernel.commit in a thread pool to avoid blocking event loop
    async def audit():
        try:
            await asyncio.to_thread(kernel.commit, messages, model, persona_data)
        except Exception as e:
            logger.error("Kernel audit failed: %s", e)

    # Track task for graceful shutdown
    task = asyncio.create_task(audit())
    background_audit_tasks.add(task)
    task.add_done_callback(background_audit_tasks.discard)

    # --- Prepare forwarding headers ---
    # Hop-by-hop headers that must not be forwarded
    hop_by_hop = {
        "host", "content-length", "connection", "authorization",
        "proxy-connection", "keep-alive", "te", "trailer", "upgrade"
    }
    headers = {}
    for k, v in request.headers.items():
        k_low = k.lower()
        if k_low not in hop_by_hop:
            headers[k] = v

    # Add tracing headers
    if settings.tuck_enable_request_id:
        headers["X-Request-ID"] = request.state.request_id
    # Add X-Forwarded-For
    client_host = request.client.host if request.client else "127.0.0.1"
    headers["X-Forwarded-For"] = client_host

    # --- Forward request to backend ---
    client: httpx.AsyncClient = request.app.state.client

    try:
        # Build request to backend
        backend_req = client.build_request(
            "POST",
            f"{backend_url}/v1/chat/completions",
            json=body,
            headers=headers,
        )
        # Send with streaming
        resp = await client.send(backend_req, stream=True)
        return StreamingResponse(
            resp.aiter_bytes(),
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )
    except httpx.TimeoutException:
        logger.error("Timeout while forwarding to %s", backend_url)
        raise HTTPException(status_code=504, detail="Backend timeout")
    except httpx.RequestError as e:
        logger.error("Request error forwarding to %s: %s", backend_url, e)
        raise HTTPException(status_code=502, detail="Backend unreachable")
    except Exception as e:
        logger.exception("Unexpected error during forwarding")
        raise HTTPException(status_code=500, detail="Internal proxy error")
