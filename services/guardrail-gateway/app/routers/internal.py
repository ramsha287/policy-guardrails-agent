"""Control plane -> gateway (X-Internal-Token). Only mounted usefully in control-plane mode.

POST /internal/simulate: see app/engine/simulation.py.
"""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from app.engine.simulation import SimulateIn, SimulationError, simulate
from app.services import Services

router = APIRouter(prefix="/internal", tags=["internal"])


def _authorized(svc: Services, token: str | None) -> bool:
    expected = svc.settings.internal_token
    return bool(expected and token and hmac.compare_digest(token, expected))


@router.post("/simulate")
async def simulate_route(
    body: SimulateIn, request: Request, x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")
) -> JSONResponse:
    svc: Services = request.app.state.services
    if not _authorized(svc, x_internal_token):
        return JSONResponse(status_code=401, content={"error": "invalid internal token"})
    try:
        return JSONResponse(content=await simulate(svc, body))
    except SimulationError as exc:
        return JSONResponse(status_code=exc.status, content={"error": exc.error})
