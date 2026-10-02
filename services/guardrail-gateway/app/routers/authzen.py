"""AuthZEN Authorization API 1.0 endpoints (see app/gateway/authzen.py for the mapping).

POST /access/v1/evaluation               one decision
POST /access/v1/evaluations              batch (max 50), options.evaluations_semantic:
                                         execute_all (default) | deny_on_first_deny | permit_on_first_permit
GET  /.well-known/authzen-configuration  PDP metadata

Authenticated with X-API-Key like /v1/guard (the AuthZEN spec leaves authentication to the
deployment). Errors in one batch item are a `false` decision for that item, never a failed batch.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.gateway.authzen import (
    SEMANTICS,
    EvaluationIn,
    EvaluationsIn,
    MappingError,
    configuration,
    denied,
    merge,
    to_authzen,
    to_guard_request,
)
from app.gateway.flow import GuardError, run_stage
from app.gateway.middleware import request_id_var, trace_id_var
from app.gateway.ratelimit import retry_after_header
from app.observability import RATE_LIMITED
from app.services import Services
from guardrail_sdk import Stage

router = APIRouter(tags=["authzen"])


def _error(status: int, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message}, headers=headers)


async def _principal(request: Request, x_api_key: str | None) -> Any:
    svc: Services = request.app.state.services
    principal = await svc.auth.authenticate(x_api_key)
    if principal is None:
        return _error(401, "Missing, invalid or revoked API key")
    return principal


def _rate_limited(request: Request, principal: Any, cost: int = 1) -> JSONResponse | None:
    """Each evaluation counts like one /v1/guard call."""
    svc: Services = request.app.state.services
    if svc.limiter is not None:
        for _ in range(cost):
            wait = svc.limiter.check(principal.key_id, principal.rate_limit_per_minute)
            if wait is not None:
                RATE_LIMITED.labels(principal.tenant_id).inc()
                return _error(429, "Rate limit exceeded for this API key", {"Retry-After": retry_after_header(wait)})
    return None


def _request_id(base: str, i: int | None = None) -> str:
    """audit.request_id is varchar(64): keep room for the batch suffix."""
    return base[:56] if i is None else f"{base[:56]}.{i}"


async def _evaluate(svc: Services, principal: Any, ev: EvaluationIn, request_id: str) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        body = to_guard_request(ev)
    except MappingError as exc:
        return denied(str(exc), "INVALID_REQUEST")
    try:
        result = await run_stage(
            svc, principal, Stage.TOOL, body, request_id=request_id, trace_id=trace_id_var.get() or "", started=started
        )
    except GuardError as exc:
        return denied(exc.message, "GATEWAY_UNAVAILABLE" if exc.status >= 500 else "INVALID_REQUEST")
    return to_authzen(result.response, accepts_modifications=bool(ev.context.get("accepts_modifications")))


@router.post("/access/v1/evaluation")
async def evaluation(request: Request, x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> JSONResponse:
    principal = await _principal(request, x_api_key)
    if isinstance(principal, JSONResponse):
        return principal
    if (limited := _rate_limited(request, principal)) is not None:
        return limited
    try:
        ev = EvaluationIn.model_validate(await request.json())
    except (ValidationError, ValueError) as exc:
        return _error(400, f"invalid AuthZEN request: {exc.__class__.__name__}")
    out = await _evaluate(request.app.state.services, principal, ev, _request_id(request_id_var.get() or ""))
    return JSONResponse(content=out)


@router.post("/access/v1/evaluations")
async def evaluations(
    request: Request, x_api_key: str | None = Header(default=None, alias="X-API-Key")
) -> JSONResponse:
    principal = await _principal(request, x_api_key)
    if isinstance(principal, JSONResponse):
        return principal
    try:
        batch = EvaluationsIn.model_validate(await request.json())
    except (ValidationError, ValueError) as exc:
        return _error(400, f"invalid AuthZEN request (max 50 evaluations): {exc.__class__.__name__}")
    if (limited := _rate_limited(request, principal, cost=max(1, len(batch.evaluations)))) is not None:
        return limited
    svc: Services = request.app.state.services
    rid = request_id_var.get() or ""
    if not batch.evaluations:  # no array: a single evaluation, answered in the single format (spec)
        return JSONResponse(content=await _evaluate(svc, principal, batch, _request_id(rid)))
    semantic = str(batch.options.get("evaluations_semantic") or "execute_all")
    if semantic not in SEMANTICS:
        return _error(400, f"options.evaluations_semantic must be one of {', '.join(SEMANTICS)}")
    results: list[dict[str, Any]] = []
    for i, item in enumerate(batch.evaluations):
        res = await _evaluate(svc, principal, merge(batch, item), _request_id(rid, i))
        results.append(res)
        if (semantic == "deny_on_first_deny" and not res["decision"]) or (
            semantic == "permit_on_first_permit" and res["decision"]
        ):
            break
    return JSONResponse(content={"evaluations": results})


@router.get("/.well-known/authzen-configuration")
async def authzen_configuration(request: Request) -> JSONResponse:
    return JSONResponse(content=configuration(str(request.base_url)))
