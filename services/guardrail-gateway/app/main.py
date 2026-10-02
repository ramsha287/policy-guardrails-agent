"""guardrail-gateway: Security Gateway + Context Builder + OPA client + Guardrail Engine (port 8100)."""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.audit.chain import AuditChain
from app.audit.spool import AuditSpool
from app.audit.writer import AuditWriter
from app.config import (
    Settings,
    check_verification_settings,
    dry_run_targets,
    get_settings,
    load_env_file,
    outbox_sinks,
    risk_config,
)
from app.context.builder import ContextBuilder
from app.context.catalog import CachedCatalog
from app.db.session import make_engine, make_sessionmaker
from app.engine.pipeline import GuardrailEngine
from app.engine.registry import PluginRegistry, SnapshotHolder
from app.engine.remote import CatalogHolder, ControlPlaneClient, ControlPlaneSync, DocCache
from app.engine.state import RedisStateStore
from app.events.relay import OutboxRelay
from app.events.sinks import RedisSink, Sink, WebhookSink
from app.gateway.auth import Authenticator
from app.gateway.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from app.gateway.proxy import ChatProxy, ProxyConfig
from app.gateway.ratelimit import RateLimiter
from app.observability import setup_logging, setup_tracing
from app.policy.opa import OpaClient
from app.repositories.api_keys import PgApiKeyStore
from app.repositories.catalog import PgCatalogStore
from app.risk.contextual import ContextualDecisions
from app.routers import authzen, escalations, guard, health, internal, proxy, verifications
from app.services import Services
from app.session.store import MemorySessionStore, RedisSessionStore
from app.verify.dryrun import SqlDryRun
from app.verify.engine import VerificationEngine
from app.verify.store import MemoryVerificationStore, RedisVerificationStore
from app.verify.user_token import UserTokenConfig, UserTokenVerifier
from guardrail_sdk import EnvSecretReader, PluginContext
from guardrail_sdk.tls import ClientTLS

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
    tls = ClientTLS.from_env().ssl_context()  # TLS_CA_FILE / TLS_CLIENT_CERT_FILE for mTLS without a mesh
    http = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout_seconds),
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        transport=httpx.AsyncHTTPTransport(retries=1, verify=tls),
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

    chain = AuditChain()
    sinks_wanted = outbox_sinks(settings)
    source = f"guardrail-gateway/{settings.gateway_id or socket.gethostname()}"
    audit = AuditWriter(
        sm,
        queue_size=settings.audit_queue_size,
        batch_size=settings.audit_batch_size,
        flush_seconds=settings.audit_flush_seconds,
        retention_months=settings.audit_retention_months,
        maintenance=settings.audit_maintenance,
        spool=AuditSpool(Path(settings.audit_spool_dir), settings.audit_spool_max_mb * 1024 * 1024)
        if settings.audit_spool_dir
        else None,
        chain=chain,
        outbox_source=source if sinks_wanted else None,
    )
    await audit.start()

    relay: OutboxRelay | None = None
    webhook_http: httpx.AsyncClient | None = None
    if sinks_wanted:
        sinks: list[Sink] = []
        if "redis" in sinks_wanted and state is not None:
            sinks.append(RedisSink(state.client))
        if "webhook" in sinks_wanted and settings.outbox_webhook_url:
            webhook_http = httpx.AsyncClient(timeout=10.0)
            sinks.append(WebhookSink(webhook_http, settings.outbox_webhook_url, settings.outbox_webhook_secret))
        relay = OutboxRelay(
            sm,
            sinks,
            source=source,
            heads=audit.written_heads,
            retention_days=settings.outbox_retention_days,
            chain_heads_seconds=settings.outbox_chain_heads_seconds,
        )
        relay.start()
        logger.info("event outbox on: sinks=%s", ",".join(s.name for s in sinks))

    sessions = RedisSessionStore(state.client) if state else MemorySessionStore(settings.session_memory_entries)
    # The IdP's JWKS is on the public internet: its own client with the system trust store (the
    # internal client may trust only the mesh CA).
    jwks_http = httpx.AsyncClient(timeout=5.0) if settings.verify_oidc_jwks_url else None
    verifier = build_verifier(settings, state.client if state else None, jwks_http)
    contextual = ContextualDecisions(
        sessions,
        mode=settings.risk_mode,
        require_bound_keys=settings.require_bound_keys,
        config=risk_config(settings),
        verifier=verifier,
    )

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
        limiter=RateLimiter(settings.guard_rate_limit_per_minute),
        readiness={
            "database": db_ok,
            "opa": opa.healthy,
            **({"redis": state.ping} if state else {}),
            **extra_ready,
        },
        registry=registry,
        control_plane=control_plane,
        contextual=contextual,
    )
    logger.info(
        "contextual decisions: risk_mode=%s, require_bound_keys=%s, session store=%s, verification=%s",
        contextual.mode,
        settings.require_bound_keys,
        "redis" if state else "memory (per replica)",
        _describe_verifier(verifier),
    )
    upstream: httpx.AsyncClient | None = None
    if settings.proxy_enabled:
        # Separate client: public TLS to the LLM provider, long timeouts, no internal client cert.
        upstream = httpx.AsyncClient(timeout=httpx.Timeout(settings.proxy_timeout_seconds, connect=10.0))
        app.state.services.proxy = ChatProxy(
            app.state.services,
            ProxyConfig(
                upstream_url=settings.proxy_upstream_url,
                upstream_api_key=settings.proxy_upstream_api_key,
                default_agent_id=settings.proxy_default_agent_id,
                models=frozenset(settings.proxy_models),
            ),
            upstream,
        )
        logger.info("proxy mode on: /v1/chat/completions -> %s", settings.proxy_upstream_url)
    logger.info("guardrail-gateway ready (env=%s, snapshot=%s)", settings.environment, snapshots.version)
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        await audit.stop()
        if relay is not None:  # after the audit drain, so the last decisions' events are in the outbox
            await relay.stop()
        if webhook_http is not None:
            await webhook_http.aclose()
        await snapshots.close()
        await http.aclose()
        if jwks_http is not None:
            await jwks_http.aclose()
        if verifier is not None and verifier.dry_run is not None:
            await verifier.dry_run.close()
        if upstream is not None:
            await upstream.aclose()
        if state is not None:
            await state.close()
        await db.dispose()


def build_verifier(settings: Settings, redis: Any, http: httpx.AsyncClient | None) -> VerificationEngine | None:
    if not settings.verification_enabled:
        return None
    check_verification_settings(settings)
    store = RedisVerificationStore(redis) if redis is not None else MemoryVerificationStore()
    targets = dry_run_targets(settings)
    tokens = UserTokenVerifier(
        UserTokenConfig(
            issuer=settings.verify_oidc_issuer,
            audience=settings.verify_oidc_audience,
            jwks_url=settings.verify_oidc_jwks_url,
            jwks_json=settings.verify_oidc_jwks_json,
            user_claim=settings.verify_user_claim,
            max_auth_age_seconds=settings.verify_max_auth_age_seconds,
            required_acr=tuple(a.strip() for a in settings.verify_required_acr.split(",") if a.strip()),
            dev_secret=settings.verify_dev_secret,
            require_nonce=settings.verify_require_nonce,
        ),
        http,
    )
    return VerificationEngine(
        store,
        dry_run=SqlDryRun(targets) if targets else None,
        user_tokens=tokens,
        max_dry_run_rows=settings.verify_dry_run_max_rows,
    )


def _describe_verifier(v: VerificationEngine | None) -> str:
    if v is None:
        return "off (verify -> human review)"
    parts = ["human review"]
    if v.dry_run is not None:
        parts.append(f"sql dry run ({len(v.dry_run.targets)} targets)")
    if v.user_confirmation_enabled:
        parts.append("user confirmation")
    return ", ".join(parts)


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
    app.include_router(verifications.router)
    app.include_router(authzen.router)
    app.include_router(internal.router)
    app.include_router(proxy.router)
    setup_tracing(app, settings.otel_endpoint)
    return app


# Run with: uvicorn --factory app.main:create_app --host 0.0.0.0 --port 8100
