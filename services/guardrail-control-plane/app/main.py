"""guardrail-control-plane (:8200): registry, assignments, publishing, catalog, review queue."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
from fastapi import FastAPI

from .api import errors
from .api.container import Container
from .api.routers import catalog, health, internal, operations, pipeline
from .config import Settings, get_settings
from .db.session import make_engine, make_sessionmaker
from .domain.crypto import PayloadCipher
from .events import NullPublisher, RedisPublisher
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


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    if not settings.internal_token or len(settings.internal_token) < 16:
        raise RuntimeError("INTERNAL_TOKEN (>= 16 chars) is required")
    engine = make_engine(settings.postgres_dsn)
    events = RedisPublisher(settings.redis_url) if settings.redis_url else NullPublisher()
    audit_engine = make_engine(settings.audit_dsn) if settings.audit_dsn else None
    http = httpx.AsyncClient(timeout=settings.http_timeout_seconds)
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
        audit_sessionmaker=make_sessionmaker(audit_engine) if audit_engine else None,
    )
    logger.info("control plane ready (two-person: %s)", ",".join(settings.two_person_environments) or "none")
    try:
        yield
    finally:
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
    app.include_router(health.router)
    for r in (catalog.router, pipeline.router, operations.router, internal.router):
        app.include_router(r, prefix=API_PREFIX)
    return app


# Run with: uvicorn --factory app.main:create_app --host 0.0.0.0 --port 8200
