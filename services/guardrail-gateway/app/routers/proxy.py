"""OpenAI-compatible `POST /v1/chat/completions` (proxy mode, off unless PROXY_ENABLED=true).

See app/gateway/proxy.py for what is checked. Authenticate with the gateway API key as the
OpenAI key (`Authorization: Bearer gk_...`) or in X-API-Key.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.gateway.middleware import request_id_var, trace_id_var
from app.gateway.proxy import openai_error
from app.gateway.ratelimit import retry_after_header
from app.observability import PROXY_REQUESTS, RATE_LIMITED
from app.services import Services

router = APIRouter(tags=["proxy"])


def _reply(status: int, body: dict, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content=body, headers=headers)


@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    svc: Services = request.app.state.services
    if svc.proxy is None:
        e = openai_error(404, "proxy mode is not enabled on this gateway (PROXY_ENABLED)", "not_found")
        return _reply(e.status, e.body)

    auth = request.headers.get("authorization", "")
    raw_key = request.headers.get("x-api-key") or (auth[7:].strip() if auth.lower().startswith("bearer ") else None)
    principal = await svc.auth.authenticate(raw_key)
    if principal is None:
        e = openai_error(401, "Missing, invalid or revoked gateway API key", "invalid_api_key")
        return _reply(e.status, e.body)
    if svc.limiter is not None:
        wait = svc.limiter.check(principal.key_id, principal.rate_limit_per_minute)
        if wait is not None:
            RATE_LIMITED.labels(principal.tenant_id).inc()
            e = openai_error(429, "Rate limit exceeded for this API key", "rate_limit_exceeded")
            return _reply(e.status, e.body, {"Retry-After": retry_after_header(wait)})

    try:
        body = await request.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        e = openai_error(400, "request body must be a JSON object", "invalid_request_error")
        return _reply(e.status, e.body)

    result = await svc.proxy.chat(
        principal, body, request.headers, request_id=request_id_var.get() or "", trace_id=trace_id_var.get() or ""
    )
    PROXY_REQUESTS.labels(str(result.status), (result.body.get("error") or {}).get("type", "ok")).inc()
    return _reply(result.status, result.body, result.headers)
