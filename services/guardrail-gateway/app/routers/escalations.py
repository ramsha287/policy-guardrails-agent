"""GET /v1/escalations/{id}: the agent polls here after a 202 (decision escalate).

pending  -> decision escalate, no payload
approved -> decision allow, payload = the held payload (use it and continue)
rejected / expired -> decision block (expired = nobody decided in time: fail-closed)
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from app.services import Services
from guardrail_sdk.documents import EscalationStatus

router = APIRouter(tags=["guard"])


@router.get("/v1/escalations/{escalation_id}", response_model=EscalationStatus)
async def escalation_status(
    escalation_id: str, request: Request, x_api_key: str | None = Header(default=None, alias="X-API-Key")
) -> JSONResponse:
    svc: Services = request.app.state.services
    principal = await svc.auth.authenticate(x_api_key)
    if principal is None:
        return JSONResponse(status_code=401, content={"error": "Missing, invalid or revoked API key"})
    if svc.control_plane is None:
        return JSONResponse(status_code=404, content={"error": "escalations need CONFIG_SOURCE=control_plane"})
    try:
        status = await svc.control_plane.review_status(escalation_id, principal.tenant_id)
    except httpx.HTTPError:
        return JSONResponse(status_code=503, content={"error": "review queue unavailable; try again"})
    if status is None:
        return JSONResponse(status_code=404, content={"error": f"escalation {escalation_id} not found"})
    if status.get("payload"):
        status["payload"] = {k: v for k, v in status["payload"].items() if k != "stage"}
    return JSONResponse(content=EscalationStatus.model_validate(status).model_dump(mode="json"))
