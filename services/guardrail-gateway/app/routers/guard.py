"""POST /v1/guard/{stage}: Security Gateway -> Context Builder -> OPA -> Guardrail Engine -> audit.

Status codes:
  200  decision allow | modify | block (guardrail block)
  202  decision escalate: held for human review; poll GET /v1/escalations/{escalation_id}
  403  decision block because OPA denied the request
  401  missing/invalid API key     422  invalid body     429  rate limit (Retry-After)
  503  no guardrail snapshot loaded
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from app.gateway.flow import GuardError, run_stage
from app.gateway.middleware import request_id_var, trace_id_var
from app.gateway.ratelimit import retry_after_header
from app.observability import RATE_LIMITED
from app.services import Services
from guardrail_sdk import GuardRequest, GuardResponse, Stage

router = APIRouter(tags=["guard"])


def _error(status: int, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message}, headers=headers)


@router.post(
    "/v1/guard/{stage}",
    response_model=GuardResponse,
    responses={202: {"model": GuardResponse}, 401: {}, 403: {"model": GuardResponse}, 422: {}, 429: {}, 503: {}},
)
async def guard(
    stage: Stage,
    body: GuardRequest,
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> JSONResponse:
    started = time.perf_counter()
    svc: Services = request.app.state.services

    principal = await svc.auth.authenticate(x_api_key)
    if principal is None:
        return _error(401, "Missing, invalid or revoked API key")
    if svc.limiter is not None:
        wait = svc.limiter.check(principal.key_id, principal.rate_limit_per_minute)
        if wait is not None:
            RATE_LIMITED.labels(principal.tenant_id).inc()
            return _error(429, "Rate limit exceeded for this API key", {"Retry-After": retry_after_header(wait)})

    try:
        result = await run_stage(
            svc,
            principal,
            stage,
            body,
            request_id=request_id_var.get() or "",
            trace_id=trace_id_var.get() or "",
            usage_bytes=int(request.headers.get("content-length") or 0),
            started=started,
        )
    except GuardError as exc:
        return _error(exc.status, exc.message)
    return JSONResponse(status_code=result.status, content=result.response.model_dump(mode="json"))
