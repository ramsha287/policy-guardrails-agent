from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from ..container import Container
from ..deps import container

router = APIRouter(tags=["ops"])
SERVICE_VERSION = "0.4.0"


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(c: Container = Depends(container)) -> JSONResponse:
    try:
        await c.ctx.store.current_catalog()
        ok = True
    except Exception:  # noqa: BLE001
        ok = False
    return JSONResponse(status_code=200 if ok else 503, content={"status": "ok" if ok else "unavailable"})


@router.get("/version")
async def version() -> dict[str, str]:
    return {"service": "guardrail-control-plane", "version": SERVICE_VERSION}
