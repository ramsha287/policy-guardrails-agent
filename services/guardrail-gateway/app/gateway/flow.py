"""One guard evaluation: Context Builder -> OPA -> Guardrail Engine -> (review queue) -> audit.

Shared by POST /v1/guard/{stage} and the OpenAI-compatible proxy (app/routers/proxy.py), so both
paths make the same decisions and write the same audit events.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydantic import ValidationError

from app.audit.digest import payload_digest
from app.engine.escalation import hold_for_review
from app.engine.pipeline import StageOutcome
from app.gateway.auth import Principal
from app.gateway.normalize import normalize_payload
from app.observability import OPA_DENY, REQUEST_LATENCY, REQUESTS, span
from guardrail_sdk import Decision, GuardPayloadIn, GuardRequest, GuardResponse, Payload, PolicyOutcome, Stage

if TYPE_CHECKING:  # app.services imports the database layer
    from app.services import Services


class GuardError(Exception):
    """Request-level failure before any decision (maps to an HTTP error, nothing audited)."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class StageResult:
    status: int  # 200 allow/modify/block, 202 escalate (held), 403 OPA denied
    response: GuardResponse


async def run_stage(
    svc: Services,
    principal: Principal,
    stage: Stage,
    body: GuardRequest,
    *,
    request_id: str,
    trace_id: str,
    usage_bytes: int = 0,
    started: float | None = None,
) -> StageResult:
    started = started if started is not None else time.perf_counter()
    snapshot = svc.snapshots.current
    if snapshot is None:
        raise GuardError(503, "No guardrail snapshot loaded; refusing to process (fail-closed)")
    try:
        payload = normalize_payload(Payload(stage=stage, **body.payload.model_dump()))
    except ValidationError as exc:
        raise GuardError(422, exc.errors()[0]["msg"]) from exc

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

    escalation_id: str | None = None
    if outcome.decision == Decision.ESCALATE:
        outcome, escalation_id = await hold_for_review(svc.control_plane, ctx, stage, outcome)
        status = 202 if escalation_id else 200

    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    released = outcome.payload if outcome.decision in (Decision.ALLOW, Decision.MODIFY) else None
    out_payload = GuardPayloadIn.model_validate(released.model_dump(exclude={"stage"})) if released else None
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
        escalation_id=escalation_id,
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
            "reason": outcome.reason + (f" [escalation {escalation_id}]" if escalation_id else ""),
            "risk_score": response.risk_score,
            "trust_score": ctx.trust_score,
            "policy_allow": policy.allow,
            "policy_reason": policy.reason,
            # Findings carry types/offsets/scores only (plugin requirement C3).
            "guardrail_results": [r.model_dump(mode="json") for r in outcome.results],
            "payload_sha256": payload_digest(payload.model_dump(mode="json")),
            "snapshot_version": snapshot.version,
            "latency_ms": latency_ms,
            "usage_bytes": usage_bytes,
        }
    )
    REQUESTS.labels(stage.value, outcome.decision.value).inc()
    REQUEST_LATENCY.labels(stage.value).observe(latency_ms)
    return StageResult(status, response)
