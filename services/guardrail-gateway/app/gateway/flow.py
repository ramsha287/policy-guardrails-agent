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
from app.policy.opa import PolicyDecision
from app.risk.contextual import ContextualDecisions, Prepared
from app.risk.decision import TableResult
from guardrail_sdk import (
    Decision,
    GuardPayloadIn,
    GuardRequest,
    GuardResponse,
    Payload,
    PolicyOutcome,
    RiskAssessment,
    RiskSignal,
    Stage,
    VerificationInfo,
)

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
    status: int  # 200 allow/modify/block, 202 escalate (held) or verify (user must confirm), 403 denied
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

    ctxd: ContextualDecisions | None = getattr(svc, "contextual", None)
    payload_sha256 = payload_digest(payload.model_dump(mode="json"))
    verification = None
    with span("gateway.guard", stage=stage.value, tenant_id=principal.tenant_id, agent_id=body.agent_id):
        built = await svc.contexts.build(principal=principal, req=body, request_id=request_id, trace_id=trace_id)
        ctx = built.context
        tool_name = payload.tool_call.name if payload.tool_call else None
        violation = ctxd.identity_violation(principal, body) if ctxd else None
        prepared = None
        if ctxd is not None and violation is None:
            prepared = await ctxd.prepare(
                principal=principal,
                body=body,
                stage=stage,
                payload=payload,
                environment=ctx.environment,
                inherent_risk=ctx.risk_score,
                base_trust=ctx.trust_score,
            )

        table: TableResult | None = None
        if violation is not None:
            # Identity binding is enforced in every mode: nothing else runs for a mismatched key.
            OPA_DENY.labels(stage.value).inc()
            policy = PolicyDecision(False, violation.reason)
            outcome = StageOutcome(Decision.BLOCK, f"identity check failed: {violation.reason}", ctx.risk_score, None)
            status = 403
        else:
            policy_input = built.policy_input(stage, tool_name)
            policy_input["identity"] = {"assurance": principal.assurance, "key_agent_id": principal.agent_id}
            if prepared is not None:
                policy_input.update(prepared.policy_input())
            with span("opa.evaluate", stage=stage.value) as s:
                policy = await svc.policy.evaluate(policy_input)
                if s is not None:
                    s.set_attribute("allow", policy.allow)

            if not policy.allow:
                OPA_DENY.labels(stage.value).inc()
                outcome = StageOutcome(Decision.BLOCK, f"policy denied: {policy.reason}", ctx.risk_score, None)
                status = 403
            else:
                outcome = await svc.engine.run(snapshot, stage, ctx, payload, policy.obligations)
                status = 200
            if ctxd is not None and prepared is not None:
                table = ctxd.decide(
                    prepared,
                    policy_allow=policy.allow,
                    engine_decision=outcome.decision,
                    accepts_obligations=bool(body.accepts_obligations),
                )
                if table is not None:  # a `verify`, or an allow that follows up an open verification
                    table, verification = await ctxd.verify(
                        prepared,
                        table,
                        principal=principal,
                        body=body,
                        stage=stage,
                        payload=payload,
                        payload_sha256=payload_sha256,
                        environment=ctx.environment,
                    )
                if table is not None and ctxd.enforcing:
                    outcome, status = _apply_table(table, outcome, status, prepared)
                    if verification is not None:
                        status = 202  # the user confirms, then the agent retries the identical request

    escalation_id: str | None = None
    if outcome.decision == Decision.ESCALATE and verification is None:
        outcome, escalation_id = await hold_for_review(
            svc.control_plane, ctx, stage, outcome, source="gateway-risk" if _risk_held(table, ctxd) else None
        )
        status = 202 if escalation_id else (403 if _risk_held(table, ctxd) else 200)

    if ctxd is not None and prepared is not None:
        await ctxd.record(
            prepared, principal=principal, body=body, stage=stage, payload=payload, final=outcome.decision
        )

    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    released = outcome.payload if outcome.decision in (Decision.ALLOW, Decision.MODIFY) else None
    out_payload = GuardPayloadIn.model_validate(released.model_dump(exclude={"stage"})) if released else None
    assessment = prepared.assessment if prepared is not None else None
    enforced_table = table if (table is not None and ctxd is not None and ctxd.enforcing) else None
    if violation is not None:
        outcome_name, reason_codes = "deny", [violation.code]
    elif enforced_table is not None:
        outcome_name = _final_outcome_name(enforced_table, outcome.decision)
        merged: list[str] = [*enforced_table.reason_codes, *(assessment.codes if assessment else [])]
        reason_codes = list(dict.fromkeys(merged))
    else:
        outcome_name = _legacy_outcome_name(outcome.decision)
        reason_codes = list(assessment.codes) if assessment else []
    obligations = enforced_table.obligations if (enforced_table and released) else {}
    risk_out = (
        RiskAssessment(
            score=assessment.score,
            band=assessment.band,
            trust=assessment.trust,
            confidence=assessment.confidence,
            mode=ctxd.mode if ctxd else "off",
            would_outcome=table.outcome if table else outcome_name,
            signals=[RiskSignal(code=x.code, points=x.points, detail=x.detail) for x in assessment.signals],
        )
        if assessment is not None
        else None
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
        escalation_id=escalation_id,
        outcome=outcome_name,
        reason_codes=reason_codes,
        obligations=obligations,
        risk=risk_out,
        assurance=principal.assurance,
        verification=VerificationInfo(
            id=verification.id,
            kind=verification.kind,
            status=verification.status,
            expires_at=verification.expires_at,
            summary=verification.summary,
            user_id=verification.user_id,
        )
        if verification is not None
        else None,
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
            "reason": outcome.reason
            + (f" [escalation {escalation_id}]" if escalation_id else "")
            + (f" [verification {verification.id}]" if verification is not None else ""),
            "risk_score": response.risk_score,
            "trust_score": ctx.trust_score,
            "policy_allow": policy.allow,
            "policy_reason": policy.reason,
            # Findings carry types/offsets/scores only (plugin requirement C3).
            "guardrail_results": [r.model_dump(mode="json") for r in outcome.results],
            "payload_sha256": payload_sha256,
            "snapshot_version": snapshot.version,
            "latency_ms": latency_ms,
            "usage_bytes": usage_bytes,
            "outcome": outcome_name,
            "reason_codes": reason_codes,
            # The descriptor holds table/column names, hosts and row counts, never values.
            "descriptor": prepared.descriptor.to_dict() if prepared is not None else None,
            "risk": risk_out.model_dump(mode="json") if risk_out is not None else None,
            "assurance": principal.assurance,
        }
    )
    REQUESTS.labels(stage.value, outcome.decision.value).inc()
    REQUEST_LATENCY.labels(stage.value).observe(latency_ms)
    return StageResult(status, response)


def _legacy_outcome_name(decision: Decision) -> str:
    return {Decision.ALLOW: "allow", Decision.MODIFY: "modify", Decision.ESCALATE: "hold", Decision.BLOCK: "deny"}[
        decision
    ]


def _final_outcome_name(table: TableResult, final: Decision) -> str:
    """The table's outcome, unless the review queue changed it (approved hold -> allow, failed -> deny)."""
    if table.legacy == final or (table.outcome in ("allow", "allow_restricted") and final == Decision.MODIFY):
        return table.outcome
    return _legacy_outcome_name(final)


def _risk_held(table: TableResult | None, ctxd: ContextualDecisions | None) -> bool:
    return bool(
        table is not None and ctxd is not None and ctxd.enforcing and table.outcome in ("hold", "verify")
        and not any(c in table.reason_codes for c in ("GUARDRAIL_ESCALATE",))
    )  # fmt: skip


def _apply_table(
    table: TableResult, outcome: StageOutcome, status: int, prepared: Prepared
) -> tuple[StageOutcome, int]:
    """Enforce mode: turn the table's outcome into the stage outcome the rest of the flow uses."""
    legacy = table.legacy
    if legacy == outcome.decision or (legacy == Decision.ALLOW and outcome.decision == Decision.MODIFY):
        return outcome, status  # guardrails already decided this (or stricter-equal)
    codes = ", ".join(table.reason_codes)
    risk = prepared.assessment.score if prepared.assessment else outcome.risk_score
    if legacy == Decision.BLOCK:
        return StageOutcome(Decision.BLOCK, f"denied by decision table ({codes})", risk, None, outcome.results), 403
    if legacy == Decision.ESCALATE and table.outcome == "verify":
        reason = f"user confirmation required ({codes})"
        return StageOutcome(Decision.ESCALATE, reason, risk, None, outcome.results), 202
    if legacy == Decision.ESCALATE:
        reason = f"held for review: risk {prepared.assessment.band if prepared.assessment else '?'} ({codes})"
        return StageOutcome(Decision.ESCALATE, reason, risk, outcome.payload, outcome.results), status
    return outcome, status
