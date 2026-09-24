"""guardrail-control-plane (:8200): registry, assignments, publishing, catalog, review queue."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from guardrail_sdk.tls import ClientTLS

from .api import errors
from .api.container import Container
from .api.routers import catalog, health, internal, operations, pipeline
from .config import Settings, get_settings
from .db.session import make_engine, make_sessionmaker
from .domain.crypto import PayloadCipher
from .events import NullPublisher, RedisPublisher
from .metrics import refresh_loop
from .services.analytics import Fetch
from .services.context import Ctx, Policy
from .store.postgres import PgStore

API_PREFIX = "/cp/v1"
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


def policy_from(settings: Settings) -> Policy:
    return Policy(
        two_person_environments=frozenset(settings.two_person_environments),
        publish_request_ttl_hours=settings.publish_request_ttl_hours,
        review_ttl_minutes=settings.review_ttl_minutes,
        gateway_stale_seconds=settings.gateway_stale_seconds,
    )


def _sql_fetcher(sessionmaker: Any) -> Fetch:
    from sqlalchemy import text

    async def fetch(sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        async with sessionmaker() as s:
            return [dict(r) for r in (await s.execute(text(sql), params)).mappings().all()]

    return fetch


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    if not settings.internal_token or len(settings.internal_token) < 16:
        raise RuntimeError("INTERNAL_TOKEN (>= 16 chars) is required")
    engine = make_engine(settings.postgres_dsn)
    events = RedisPublisher(settings.redis_url) if settings.redis_url else NullPublisher()
    audit_engine = make_engine(settings.audit_dsn) if settings.audit_dsn else None
    http = httpx.AsyncClient(timeout=settings.http_timeout_seconds, verify=ClientTLS.from_env().ssl_context())
    app.state.container = Container(
        ctx=Ctx(
            store=PgStore(make_sessionmaker(engine)),
            events=events,
            cipher=PayloadCipher(settings.review_encryption_key),
            policy=policy_from(settings),
        ),
        internal_token=settings.internal_token,
        http=http,
        gateway_url=settings.gateway_url,
        gateway_urls=settings.gateway_urls,
        analytics_fetch=_sql_fetcher(make_sessionmaker(audit_engine)) if audit_engine else None,
    )
    logger.info("control plane ready (two-person: %s)", ",".join(settings.two_person_environments) or "none")
    metrics_task = asyncio.create_task(refresh_loop(app.state.container.ctx), name="metrics")
    try:
        yield
    finally:
        metrics_task.cancel()
        await http.aclose()
        if isinstance(events, RedisPublisher):
            await events.close()
        if audit_engine is not None:
            await audit_engine.dispose()
        await engine.dispose()


def create_app(settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    settings = settings or get_settings()
    _setup_logging(settings.log_level)
    app = FastAPI(
        title="Guardrail Control Plane",
        version=health.SERVICE_VERSION,
        lifespan=None if container is not None else _lifespan,
    )
    app.state.settings = settings
    if container is not None:
        app.state.container = container
    errors.register(app)
    app.middleware("http")(_security_headers)
    app.include_router(health.router)
    for r in (catalog.router, pipeline.router, operations.router, internal.router):
        app.include_router(r, prefix=API_PREFIX)
    _mount_console(app, Path(settings.console_dir))
    return app


# The console only talks to this origin; nothing is loaded from elsewhere.
CONSOLE_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


async def _security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    response = await call_next(request)
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("X-Frame-Options", "DENY")
    path = request.url.path
    if path.startswith("/console"):
        h.setdefault("Content-Security-Policy", CONSOLE_CSP)
        # hashed assets can be cached forever (only real ones: never cache a 404 during a rollout);
        # index.html and everything else must always be revalidated
        immutable = path.startswith("/console/assets/") and response.status_code in (200, 304)
        h["Cache-Control"] = "public, max-age=31536000, immutable" if immutable else "no-cache"
    elif path.startswith(API_PREFIX):
        h.setdefault("Cache-Control", "no-store")
    return response


def _mount_console(app: FastAPI, directory: Path) -> None:
    """Serve the built console at /console (the human review UI lives at /console/#/reviews)."""
    if not (directory / "index.html").is_file():
        logger.info("console not found at %s; /console is disabled", directory)
        return
    app.mount("/console", StaticFiles(directory=directory, html=True), name="console")

    @app.get("/", include_in_schema=False)
    async def _root() -> RedirectResponse:
        return RedirectResponse("/console/")

    @app.get("/review", include_in_schema=False)
    async def _review() -> RedirectResponse:
        return RedirectResponse("/console/#/reviews")


# Run with: python -m app.serve (or uvicorn --factory app.main:create_app --port 8200)
