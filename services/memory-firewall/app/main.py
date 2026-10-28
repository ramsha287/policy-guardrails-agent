"""memory-firewall (:8300): the Memory Firewall library behind an authenticated HTTP API.

    GET  /health                    liveness
    GET  /ready                     signing keys loaded and the data directory writable
    GET  /version
    GET  /v1/status                 library version, signing key id, trusted sources, counters
    POST /v1/memory/inspect         authorized-writer gate + per-source trust (+ optional scan) per item
    POST /v1/memory/scan            heuristic scan only (no state change)
    GET  /v1/provenance/{doc_id}    verify the signed provenance record of an admitted item
    GET  /v1/events?limit=          newest entries of the JSONL event log
    POST /v1/selftest/checkpoint    run the five checkpoint attacks against GuardedSaver

Everything under /v1 needs X-API-Key. Responses never echo memory text; findings name the
matched heuristic, events carry ids and reasons only.
"""

from __future__ import annotations

import hmac
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings, get_settings
from .firewall import MemoryFirewall, SelfTestError, library_version

SERVICE_VERSION = "1.0.0"
logger = logging.getLogger(__name__)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out)


def _setup_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


# ---- request bodies ------------------------------------------------------------------------------


class InspectItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=300)
    text: str = ""
    # The library's labels are system, user, tool and web; anything else is treated as untrusted.
    source: str = Field(min_length=1, max_length=40)
    writer: str = Field(min_length=1, max_length=200)
    authorized: bool


class InspectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[InspectItem] = Field(min_length=1)
    scan: bool = True


class ScanItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=300)
    text: str


class ScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ScanItem] = Field(min_length=1)


# ---- dependencies ------------------------------------------------------------------------------------


def firewall(request: Request) -> MemoryFirewall:
    return request.app.state.firewall


def settings(request: Request) -> Settings:
    return request.app.state.settings


async def authenticated(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"), s: Settings = Depends(settings)
) -> None:
    if not x_api_key or not s.api_key or not hmac.compare_digest(x_api_key, s.api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")


def _limits(s: Settings, items: list[Any]) -> None:
    if len(items) > s.max_items:
        raise HTTPException(status_code=413, detail=f"at most {s.max_items} items per request")
    too_long = [it.id for it in items if len(it.text) > s.max_text_chars]
    if too_long:
        raise HTTPException(status_code=413, detail=f"{len(too_long)} item(s) exceed {s.max_text_chars} characters")


# ---- routes --------------------------------------------------------------------------------------------

ops = APIRouter(tags=["ops"])
api = APIRouter(prefix="/v1", tags=["memory"], dependencies=[Depends(authenticated)])


@ops.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@ops.get("/ready")
async def ready(fw: MemoryFirewall = Depends(firewall)) -> JSONResponse:
    ok = fw.ready()
    return JSONResponse(status_code=200 if ok else 503, content={"status": "ok" if ok else "unavailable"})


@ops.get("/version")
async def version() -> dict[str, str]:
    return {"service": "memory-firewall", "version": SERVICE_VERSION, "library_version": library_version()}


@api.get("/status")
def status(fw: MemoryFirewall = Depends(firewall)) -> dict[str, Any]:
    return {**fw.status(), "version": SERVICE_VERSION}


@api.post("/memory/inspect")
def inspect(body: InspectIn, fw: MemoryFirewall = Depends(firewall), s: Settings = Depends(settings)) -> dict[str, Any]:
    _limits(s, body.items)
    verdicts = fw.inspect([it.model_dump() for it in body.items], scan=body.scan)
    results = [asdict(v) for v in verdicts]
    return {
        "results": results,
        "summary": {
            "items": len(results),
            "admitted": sum(v.admitted for v in verdicts),
            "quarantined": sum(not v.admitted for v in verdicts),
            "scan_flagged": sum(bool(v.scan_findings) for v in verdicts),
        },
        "key_id": fw.key_id,
    }


@api.post("/memory/scan")
def scan(body: ScanIn, fw: MemoryFirewall = Depends(firewall), s: Settings = Depends(settings)) -> dict[str, Any]:
    _limits(s, body.items)
    flagged = fw.scan([it.model_dump() for it in body.items])
    return {
        "results": [{"id": it.id, "findings": flagged.get(it.id, [])} for it in body.items],
        "summary": {"items": len(body.items), "flagged": sum(1 for it in body.items if it.id in flagged)},
    }


@api.get("/provenance/{doc_id}")
def provenance(doc_id: str, fw: MemoryFirewall = Depends(firewall)) -> dict[str, Any]:
    return fw.verify_provenance(doc_id)


@api.get("/events")
def events(limit: int = Query(50, ge=1, le=500), fw: MemoryFirewall = Depends(firewall)) -> dict[str, Any]:
    return {"events": fw.recent_events(limit)}


@api.post("/selftest/checkpoint")
async def selftest(fw: MemoryFirewall = Depends(firewall), s: Settings = Depends(settings)) -> dict[str, Any]:
    try:
        return await fw.self_test(s.selftest_timeout_seconds)
    except SelfTestError as exc:
        logger.error("checkpoint self-test failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---- app -------------------------------------------------------------------------------------------------


def _register_errors(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def _http(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.detail}, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        errs = [f"{'.'.join(str(p) for p in e.get('loc', []) if p != 'body')}: {e.get('msg')}" for e in exc.errors()]
        return JSONResponse(status_code=422, content={"error": "invalid request", "errors": errs})

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled error: %s", exc.__class__.__name__, exc_info=exc)
        return JSONResponse(status_code=500, content={"error": "Internal server error"})


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    _setup_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if not settings.api_key or len(settings.api_key) < 16:
            raise RuntimeError("MEMORY_FIREWALL_API_KEY (>= 16 chars) is required")
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        app.state.firewall = MemoryFirewall(
            settings.data_dir, settings.trusted_sources, settings.max_provenance_records
        )
        logger.info(
            "memory firewall ready (key %s, trusted sources %s)",
            app.state.firewall.key_id,
            ",".join(settings.trusted_sources),
        )
        yield

    app = FastAPI(title="Memory Firewall", version=SERVICE_VERSION, lifespan=lifespan)
    app.state.settings = settings
    _register_errors(app)
    app.include_router(ops)
    app.include_router(api)
    return app


# Run with: uvicorn --factory app.main:create_app --host 0.0.0.0 --port 8300
