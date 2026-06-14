from __future__ import annotations

import hmac
import logging
import os
import time
import uuid
from collections import defaultdict
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from hydra.api.metrics import setup_metrics
from hydra.api.websocket import ws_handler
from hydra.distribution.chunk import ChunkManager
from hydra.distribution.worker_manager import WorkerManager
from hydra.engines.hashcat import HashcatEngine
from hydra.engines.jtr import JtrEngine
from hydra.engines.python_engine import PythonEngine
from hydra.knowledge.database import Database
from hydra.knowledge.repository import KnowledgeRepository
from hydra.models.base import HashType, Session, SessionConfig
from hydra.pipeline.executor import PipelineExecutor
from hydra.planner.heuristic import HeuristicPlanner
from hydra.plugins.loader import PluginLoader

logger = logging.getLogger(__name__)

_API_KEY = os.environ.get("HYDRA_API_KEY", "")
_RATE_LIMIT = int(os.environ.get("HYDRA_RATE_LIMIT", "100"))
_MAX_HASHES = int(os.environ.get("HYDRA_MAX_HASHES", "1000"))
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def _check_auth(request: Request) -> None:
    if _API_KEY:
        key = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(key, _API_KEY):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _check_rate_limit(request: Request) -> None:
    if _RATE_LIMIT <= 0:
        return
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = _rate_buckets[client_ip]
    bucket[:] = [t for t in bucket if now - t < 60]
    if len(bucket) >= _RATE_LIMIT:
        raise HTTPException(status_code=429, detail=f"Rate limit ({_RATE_LIMIT}/min) exceeded")
    bucket.append(now)


_MAX_HASH_LENGTH = 512
_MAX_TIMEOUT = 86400  # 24 hours


class CrackRequest(BaseModel):
    hashes: list[str]
    hash_type: str | None = None
    wordlists: list[str] = []
    timeout: int = Field(default=3600, ge=1, le=_MAX_TIMEOUT)
    distribution: bool = False

    @field_validator("hashes")
    @classmethod
    def validate_hashes(cls, v: list[str]) -> list[str]:
        for h in v:
            if not h or not h.strip():
                raise ValueError("hashes must not contain empty strings")
            if len(h) > _MAX_HASH_LENGTH:
                raise ValueError(f"hash exceeds maximum length of {_MAX_HASH_LENGTH} characters")
        return [h.strip() for h in v]

    @field_validator("wordlists")
    @classmethod
    def validate_wordlists(cls, v: list[str]) -> list[str]:
        for w in v:
            if len(w) > 255:
                raise ValueError("wordlist path exceeds maximum length of 255 characters")
        return v


class CrackResponse(BaseModel):
    session_id: str
    hash_type: str
    total: int
    cracked: int
    phases_completed: int
    summary: str
    results: list[dict[str, str]] = []


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    db_path = Path("/data") if Path("/data").exists() else Path.cwd()
    app.state.db = Database(f"sqlite:///{db_path}/hydra.db")
    app.state.kb = KnowledgeRepository(app.state.db)
    app.state.engines = {}
    hashcat = HashcatEngine()
    try:
        await hashcat.detect()
        app.state.engines["hashcat"] = hashcat
    except (FileNotFoundError, OSError):
        pass
    john = JtrEngine()
    try:
        await john.detect()
        app.state.engines["john"] = john
    except (FileNotFoundError, OSError):
        pass
    app.state.worker_manager = WorkerManager()
    app.state.chunk_manager = ChunkManager()
    app.state.engines.setdefault("python", PythonEngine())

    metrics = setup_metrics(app)
    app.state.metrics = metrics

    plugin_loader = PluginLoader("/plugins")
    discovered = plugin_loader.discover()
    app.state.plugins = plugin_loader
    for plugin in discovered:
        try:
            plugin.on_startup(app)
        except Exception:
            logger.exception("Plugin %s failed to start", plugin.name)

    yield

    for plugin in discovered:
        try:
            plugin.on_shutdown(app)
        except Exception:
            logger.exception("Plugin %s failed to shutdown", plugin.name)


app = FastAPI(title="HYDRA", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def auth_and_rate_limit(request: Request, call_next: Any) -> JSONResponse:
    if request.url.path not in ("/health", "/"):
        try:
            _check_auth(request)
            _check_rate_limit(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)  # type: ignore[no-any-return]


@app.get("/")
async def root() -> dict[str, Any]:
    engine_names = list(app.state.engines.keys())
    return {"service": "HYDRA", "version": "0.1.0", "engines": engine_names}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/engines")
async def list_engines() -> dict[str, list[str]]:
    return {"engines": list(app.state.engines.keys())}


@app.post("/crack", response_model=CrackResponse)
async def crack(req: CrackRequest) -> CrackResponse:
    if not app.state.engines:
        raise HTTPException(status_code=503, detail="No cracking engines available")

    if not req.hashes:
        raise HTTPException(status_code=400, detail="At least one hash is required")

    if len(req.hashes) > _MAX_HASHES:
        raise HTTPException(
            status_code=400,
            detail=f"Too many hashes: {len(req.hashes)} submitted, maximum allowed is {_MAX_HASHES}",
        )

    if req.hash_type:
        htype = HashType(req.hash_type)
    else:
        engine = next(iter(app.state.engines.values()))
        results = await engine.identify_hashes(req.hashes[:1])
        htype = results[0][1] if results else HashType.UNKNOWN

    if htype == HashType.UNKNOWN:
        raise HTTPException(status_code=400, detail="Could not identify hash type")

    session_id = uuid.uuid4().hex[:12]
    config = SessionConfig(
        hash_type=htype,
        hashes=req.hashes,
        wordlists=req.wordlists,
        timeout_seconds=req.timeout,
        distribution=req.distribution,
    )
    session = Session(id=session_id, config=config, total_hashes=len(req.hashes))

    planner = HeuristicPlanner(app.state.engines)
    plan = planner.plan(config)
    executor = PipelineExecutor(plan, session)
    result = await executor.run()

    app.state.kb.save_session(result)
    if result.results:
        app.state.kb.save_results(result.results, session_id)

    app.state.metrics.record_crack(result.cracked_count)

    for plugin in app.state.plugins.get_all():
        try:
            for r in result.results:
                plugin.on_result({
                    "hash": r.hash_, "password": r.password,
                    "hash_type": r.hash_type.value, "phase": r.phase.name,
                })
        except Exception:
            logger.exception("Plugin %s failed to process result", plugin.name)

    return CrackResponse(
        session_id=session_id,
        hash_type=htype.value,
        total=result.total_hashes,
        cracked=result.cracked_count,
        phases_completed=executor.phase_count,
        summary=executor.phase_summary,
        results=[{"hash": r.hash_[:16], "password": r.password} for r in result.results],
    )


@app.get("/sessions")
async def list_sessions(hash_type: str | None = None) -> dict[str, list[dict[str, Any]]]:
    if hash_type:
        records = app.state.kb.get_session_history(hash_type)
    else:
        records = app.state.kb.get_all_sessions()
    return {
        "sessions": [
            {
                "id": r.id, "hash_type": r.hash_type, "cracked": r.cracked_count,
                "total": r.total_hashes,
                "started": r.started_at.isoformat() if r.started_at else None,
            }
            for r in records
        ]
    }


@app.get("/rules/top")
async def top_rules(hash_type: str = "", limit: int = 20) -> dict[str, list[dict[str, Any]]]:
    if not hash_type:
        return {"rules": []}
    rules = app.state.kb.get_best_rules(hash_type, limit)
    return {"rules": [{"rule": r, "score": s} for r, s in rules]}


@app.get("/stats")
async def stats() -> dict[str, Any]:
    return {
        "engines": list(app.state.engines.keys()),
        "avg_crack_rate": {
            ht.value: app.state.kb.get_average_crack_rate(ht.value)
            for ht in HashType
            if ht != HashType.UNKNOWN
        },
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await ws_handler(websocket)
