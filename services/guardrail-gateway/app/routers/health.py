from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.services import Services
from guardrail_sdk import SDK_VERSION

router = APIRouter(tags=["ops"])

SERVICE_VERSION = "0.5.0"


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness: the process is up."""
    return {"status": "ok"}


@router.get("/ready")
async def ready(request: Request) -> JSONResponse:
    """Readiness: snapshot loaded and dependencies reachable. Kubernetes routes traffic on this."""
    svc: Services = request.app.state.services
    checks: dict[str, bool] = {"snapshot": svc.snapshots.current is not None}
    names = list(svc.readiness)
    results = await asyncio.gather(*(svc.readiness[n]() for n in names), return_exceptions=True)
    for n, r in zip(names, results, strict=True):
        checks[n] = r is True
    ok = all(checks.values())
    body = {
        "status": "ok" if ok else "unavailable",
        "checks": checks,
        "snapshot_version": svc.snapshots.version,
        "snapshot_error": svc.snapshots.last_error,
    }
    return JSONResponse(status_code=200 if ok else 503, content=body)


@router.get("/version")
async def version(request: Request) -> dict[str, str | None]:
    svc: Services = request.app.state.services
    return {
        "service": "guardrail-gateway",
        "version": SERVICE_VERSION,
        "sdk_version": SDK_VERSION,
        "environment": svc.settings.environment,
        "snapshot_version": svc.snapshots.version,
    }


@router.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
