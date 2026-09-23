"""guardrail-gateway: Security Gateway + Context Builder + OPA client + Guardrail Engine (port 8100)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.audit.writer import AuditWriter
from app.config import Settings, get_settings, load_env_file
from app.context.builder import ContextBuilder
from app.context.catalog import CachedCatalog
from app.db.session import make_engine, make_sessionmaker
from app.engine.pipeline import GuardrailEngine
from app.engine.registry import PluginRegistry, SnapshotHolder
from app.engine.state import RedisStateStore
from app.gateway.auth import Authenticator
from app.gateway.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from app.observability import setup_logging, setup_tracing
from app.policy.opa import OpaClient
from app.repositories.api_keys import PgApiKeyStore
from app.repositories.catalog import PgCatalogStore
from app.routers import guard, health
from app.services import Services
from guardrail_sdk import EnvSecretReader, PluginContext

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _production_lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    load_env_file(settings.bootstrap_env_file)

    db = make_engine(settings.postgres_dsn)
    sm = make_sessionmaker(db)
    http = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout_seconds),
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        transport=httpx.AsyncHTTPTransport(retries=1),
    )
    state = RedisStateStore(settings.redis_url) if settings.redis_url else None
    plugin_ctx = PluginContext(http=http, secrets=EnvSecretReader(), state=state, environment=settings.environment)
    registry = PluginRegistry(settings.plugin_dirs, plugin_ctx)
    registry.discover()
    snapshots = SnapshotHolder(registry, settings.snapshot_path, settings.environment)
    await snapshots.load()
    watcher = asyncio.create_task(snapshots.watch(settings.snapshot_reload_seconds), name="snapshot-watch")

    audit = AuditWriter(
        sm,
        queue_size=settings.audit_queue_size,
        batch_size=settings.audit_batch_size,
        flush_seconds=settings.audit_flush_seconds,
        retention_months=settings.audit_retention_months,
    )
    await audit.start()

    opa = OpaClient(http, settings.opa_url, settings.opa_decision_path, settings.opa_timeout_ms)

    async def db_ok() -> bool:
        try:
            async with sm() as s:
                await s.execute(text("SELECT 1"))
            return True
        except Exception:  # noqa: BLE001
            return False

    app.state.services = Services(
        settings=settings,
        auth=Authenticator(PgApiKeyStore(sm), ttl_seconds=settings.auth_cache_ttl_seconds),
        contexts=ContextBuilder(
            CachedCatalog(PgCatalogStore(sm), ttl_seconds=settings.catalog_cache_ttl_seconds),
            settings.environment,
        ),
        policy=opa,
        engine=GuardrailEngine(default_timeout_ms=settings.default_guardrail_timeout_ms),
        snapshots=snapshots,
        audit=audit,
        readiness={"database": db_ok, "opa": opa.healthy, **({"redis": state.ping} if state else {})},
    )
    logger.info("guardrail-gateway ready (env=%s, snapshot=%s)", settings.environment, snapshots.version)
    try:
        yield
    finally:
        watcher.cancel()
        await audit.stop()
        await snapshots.close()
        await http.aclose()
        if state is not None:
            await state.close()
        await db.dispose()


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    """`services` lets tests inject fakes; production builds them in the lifespan."""
    settings = settings or get_settings()
    setup_logging(settings.log_level)
    app = FastAPI(
        title="Guardrail Gateway",
        version=health.SERVICE_VERSION,
        lifespan=None if services is not None else _production_lifespan,
    )
    app.state.settings = settings
    if services is not None:
        app.state.services = services

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(RequestContextMiddleware)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo the request body back or into logs: it may contain PII.
        err = exc.errors()[0]
        field = ".".join(str(p) for p in err.get("loc", []) if p != "body")
        return JSONResponse(status_code=422, content={"error": f"{field}: {err.get('msg')}"})

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled error: %s", exc.__class__.__name__, exc_info=exc)
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

    app.include_router(health.router)
    app.include_router(guard.router)
    setup_tracing(app, settings.otel_endpoint)
    return app


# Run with: uvicorn --factory app.main:create_app --host 0.0.0.0 --port 8100
