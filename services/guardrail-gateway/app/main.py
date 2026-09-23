"""guardrail-gateway: Security Gateway + Context Builder + OPA client + Guardrail Engine (port 8100)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
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
from app.engine.remote import CatalogHolder, ControlPlaneClient, ControlPlaneSync, DocCache
from app.engine.state import RedisStateStore
from app.gateway.auth import Authenticator
from app.gateway.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from app.observability import setup_logging, setup_tracing
from app.policy.opa import OpaClient
from app.repositories.api_keys import PgApiKeyStore
from app.repositories.catalog import PgCatalogStore
from app.routers import escalations, guard, health, internal
from app.services import Services
from guardrail_sdk import EnvSecretReader, PluginContext

logger = logging.getLogger(__name__)


def _is_set(getter: Callable[[], object]) -> Callable[[], Awaitable[bool]]:
    async def check() -> bool:
        return getter() is not None

    return check


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
    tasks: list[asyncio.Task[None]] = []
    control_plane: ControlPlaneClient | None = None

    if settings.config_source == "control_plane":
        if not (settings.control_plane_url and settings.internal_token):
            raise RuntimeError("CONFIG_SOURCE=control_plane needs CONTROL_PLANE_URL and INTERNAL_TOKEN")
        snapshots = SnapshotHolder(registry, None, settings.environment)
        catalog_holder = CatalogHolder(settings.environment)
        control_plane = ControlPlaneClient(http, settings.control_plane_url, settings.internal_token)
        sync = ControlPlaneSync(
            control_plane,
            snapshots,
            catalog_holder,
            registry,
            DocCache(settings.cache_dir, settings.environment),
            environment=settings.environment,
            gateway_id=settings.gateway_id,
        )
        await sync.start()
        tasks.append(asyncio.create_task(sync.poll(settings.cp_poll_seconds), name="cp-poll"))
        tasks.append(asyncio.create_task(sync.heartbeat(settings.heartbeat_seconds), name="cp-heartbeat"))
        if settings.redis_url:
            tasks.append(asyncio.create_task(sync.listen(settings.redis_url), name="cp-events"))
        # Short caches: revocations and score edits arrive through the catalog within seconds.
        auth = Authenticator(catalog_holder, ttl_seconds=5, negative_ttl_seconds=2)
        scoring = CachedCatalog(catalog_holder, ttl_seconds=2)
        extra_ready = {"catalog": _is_set(lambda: catalog_holder.version)}
    else:
        snapshots = SnapshotHolder(registry, settings.snapshot_path, settings.environment)
        await snapshots.load()
        tasks.append(asyncio.create_task(snapshots.watch(settings.snapshot_reload_seconds), name="snapshot-watch"))
        auth = Authenticator(PgApiKeyStore(sm), ttl_seconds=settings.auth_cache_ttl_seconds)
        scoring = CachedCatalog(PgCatalogStore(sm), ttl_seconds=settings.catalog_cache_ttl_seconds)
        extra_ready = {}

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
        auth=auth,
        contexts=ContextBuilder(scoring, settings.environment),
        policy=opa,
        # With a review queue, ESCALATE holds the request for a human; without one it blocks.
        engine=GuardrailEngine(
            default_timeout_ms=settings.default_guardrail_timeout_ms, escalate_as_block=control_plane is None
        ),
        snapshots=snapshots,
        audit=audit,
        readiness={
            "database": db_ok,
            "opa": opa.healthy,
            **({"redis": state.ping} if state else {}),
            **extra_ready,
        },
        registry=registry,
        control_plane=control_plane,
    )
    logger.info("guardrail-gateway ready (env=%s, snapshot=%s)", settings.environment, snapshots.version)
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
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
    app.include_router(escalations.router)
    app.include_router(internal.router)
    setup_tracing(app, settings.otel_endpoint)
    return app


# Run with: uvicorn --factory app.main:create_app --host 0.0.0.0 --port 8100
