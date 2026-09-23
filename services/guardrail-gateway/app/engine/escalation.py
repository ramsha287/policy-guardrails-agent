"""ESCALATE handling: hold the request in the control plane's review queue (fail-closed)."""

from __future__ import annotations

import json

import httpx

from app.engine.pipeline import StageOutcome
from app.engine.remote import ControlPlaneClient
from guardrail_sdk import Decision, Payload, SecurityContext, Stage

PREVIEW_CHARS = 500


def preview_of(payload: Payload) -> str:
    """Short text for the reviewer's list view (the payload after any redaction guardrails)."""
    if payload.text is not None:
        text = payload.text
    elif payload.messages:
        text = payload.messages[-1].content
    elif payload.chunks:
        text = " | ".join(c.text for c in payload.chunks)
    elif payload.tool_call is not None:
        text = json.dumps(payload.tool_call.model_dump(mode="json"), default=str)
    else:
        text = ""
    return text[:PREVIEW_CHARS]


async def hold_for_review(
    control_plane: ControlPlaneClient | None, ctx: SecurityContext, stage: Stage, outcome: StageOutcome
) -> tuple[StageOutcome, str | None]:
    """File a review with the held payload. If the queue is unavailable, block (fail-closed)."""
    deciding = next((r for r in outcome.results if r.decision == Decision.ESCALATE and r.mode == "enforce"), None)
    if control_plane is None or outcome.payload is None:
        return StageOutcome(
            Decision.BLOCK, f"{outcome.reason} (no review queue; blocking)", outcome.risk_score, None, outcome.results
        ), None
    try:
        created = await control_plane.create_review(
            {
                "tenant_id": ctx.tenant_id,
                "environment": ctx.environment,
                "request_id": ctx.request_id,
                "stage": stage.value,
                "agent_id": ctx.agent_id,
                "guardrail_id": deciding.guardrail_id if deciding else "unknown",
                "reason": outcome.reason,
                "risk_score": outcome.risk_score,
                "payload": outcome.payload.model_dump(mode="json"),
                "preview": preview_of(outcome.payload),
            }
        )
    except httpx.HTTPError as exc:
        reason = f"{outcome.reason} (review queue unavailable: {exc.__class__.__name__}; blocking)"
        return StageOutcome(Decision.BLOCK, reason, outcome.risk_score, None, outcome.results), None
    return outcome, str(created["escalation_id"])
