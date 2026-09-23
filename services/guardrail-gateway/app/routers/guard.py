"""POST /v1/guard/{stage}: Security Gateway -> Context Builder -> OPA -> Guardrail Engine -> audit.

Status codes:
  200  decision allow | modify | block (guardrail block)
  403  decision block because OPA denied the request
  401  missing/invalid API key     422  invalid body     503  no guardrail snapshot loaded
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.audit.writer import payload_digest
from app.engine.pipeline import StageOutcome
from app.gateway.middleware import request_id_var, trace_id_var
from app.gateway.normalize import normalize_payload
from app.observability import OPA_DENY, REQUEST_LATENCY, REQUESTS, span
from app.services import Services
from guardrail_sdk import Decision, GuardPayloadIn, GuardRequest, GuardResponse, Payload, PolicyOutcome, Stage

router = APIRouter(tags=["guard"])


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


@router.post(
    "/v1/guard/{stage}",
    response_model=GuardResponse,
    responses={401: {}, 403: {"model": GuardResponse}, 422: {}, 503: {}},
)
async def guard(
    stage: Stage,
    body: GuardRequest,
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> JSONResponse:
    started = time.perf_counter()
    svc: Services = request.app.state.services
    request_id = request_id_var.get() or ""
    trace_id = trace_id_var.get() or ""

    principal = await svc.auth.authenticate(x_api_key)
    if principal is None:
        return _error(401, "Missing, invalid or revoked API key")

    snapshot = svc.snapshots.current
    if snapshot is None:
        return _error(503, "No guardrail snapshot loaded; refusing to process (fail-closed)")

    try:
        payload = normalize_payload(Payload(stage=stage, **body.payload.model_dump()))
    except ValidationError as exc:
        return _error(422, exc.errors()[0]["msg"])

    with span("gateway.guard", stage=stage.value, tenant_id=principal.tenant_id, agent_id=body.agent_id):
        built = await svc.contexts.build(principal=principal, req=body, request_id=request_id, trace_id=trace_id)
        ctx = built.context
        tool_name = payload.tool_call.name if payload.tool_call else None

        with span("opa.evaluate", stage=stage.value) as s:
            policy = await svc.policy.evaluate(built.policy_input(stage, tool_name))
            if s is not None:
                s.set_attribute("allow", policy.allow)

        if not policy.allow:
            OPA_DENY.labels(stage.value).inc()
            outcome = StageOutcome(Decision.BLOCK, f"policy denied: {policy.reason}", ctx.risk_score, None)
            status = 403
        else:
            outcome = await svc.engine.run(snapshot, stage, ctx, payload, policy.obligations)
            status = 200

    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    out_payload = (
        GuardPayloadIn.model_validate(outcome.payload.model_dump(exclude={"stage"})) if outcome.payload else None
    )
    response = GuardResponse(
        request_id=request_id,
        trace_id=trace_id,
        stage=stage,
        decision=outcome.decision,
        reason=outcome.reason,
        risk_score=max(ctx.risk_score, outcome.risk_score),
        trust_score=ctx.trust_score,
        payload=out_payload,
        policy=PolicyOutcome(allow=policy.allow, reason=policy.reason, obligations=policy.obligations),
        results=outcome.results,
        snapshot_version=snapshot.version,
    )

    svc.audit.submit(
        {
            "tenant_id": ctx.tenant_id,
            "request_id": request_id,
            "trace_id": trace_id,
            "stage": stage.value,
            "environment": ctx.environment,
            "agent_id": ctx.agent_id,
            "user_id": ctx.user_id,
            "session_id": ctx.session_id,
            "action": ctx.action,
            "resource": ctx.resource,
            "decision": outcome.decision.value,
            "reason": outcome.reason,
            "risk_score": response.risk_score,
            "trust_score": ctx.trust_score,
            "policy_allow": policy.allow,
            "policy_reason": policy.reason,
            # Findings carry types/offsets/scores only (plugin requirement C3).
            "guardrail_results": [r.model_dump(mode="json") for r in outcome.results],
            "payload_sha256": payload_digest(payload.model_dump(mode="json")),
            "snapshot_version": snapshot.version,
            "latency_ms": latency_ms,
            "usage_bytes": int(request.headers.get("content-length") or 0),
        }
    )
    REQUESTS.labels(stage.value, outcome.decision.value).inc()
    REQUEST_LATENCY.labels(stage.value).observe(latency_ms)
    return JSONResponse(status_code=status, content=response.model_dump(mode="json"))
