"""Control plane -> gateway (X-Internal-Token). Only mounted usefully in control-plane mode.

POST /internal/simulate: run a request through a *draft* snapshot (and optionally a draft
catalog) with the real plugins and OPA, without enforcing, auditing or filing reviews.
"""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from app.context.builder import ContextBuilder
from app.context.catalog import CachedCatalog
from app.engine.pipeline import GuardrailEngine, StageOutcome
from app.engine.remote import CatalogHolder
from app.engine.snapshot import parse_snapshot
from app.gateway.auth import Principal
from app.gateway.normalize import normalize_payload
from app.services import Services
from guardrail_sdk import Decision, GuardPayloadIn, GuardRequest, Payload, Stage

router = APIRouter(prefix="/internal", tags=["internal"])


class SimulateIn(BaseModel):
    snapshot: dict[str, Any]
    catalog: dict[str, Any] | None = None
    tenant_id: str
    stage: Stage
    request: GuardRequest


def _authorized(svc: Services, token: str | None) -> bool:
    expected = svc.settings.internal_token
    return bool(expected and token and hmac.compare_digest(token, expected))


@router.post("/simulate")
async def simulate(
    body: SimulateIn, request: Request, x_internal_token: str | None = Header(default=None, alias="X-Internal-Token")
) -> JSONResponse:
    svc: Services = request.app.state.services
    if not _authorized(svc, x_internal_token):
        return JSONResponse(status_code=401, content={"error": "invalid internal token"})
    if svc.registry is None:
        return JSONResponse(status_code=503, content={"error": "simulation is not available on this gateway"})
    env = svc.settings.environment
    try:
        compiled = await svc.registry.compile(parse_snapshot(body.snapshot), env)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=422, content={"error": f"snapshot does not compile here: {exc}"})
    try:
        contexts = svc.contexts
        if body.catalog is not None:
            holder = CatalogHolder(env)
            if not holder.apply(body.catalog):
                return JSONResponse(status_code=422, content={"error": "invalid catalog document"})
            contexts = ContextBuilder(CachedCatalog(holder, ttl_seconds=0), env)
        try:
            payload = normalize_payload(Payload(stage=body.stage, **body.request.payload.model_dump()))
        except ValidationError as exc:
            return JSONResponse(status_code=422, content={"error": exc.errors()[0]["msg"]})
        principal = Principal("simulation", body.tenant_id, "simulation", frozenset({"guard:invoke"}))
        built = await contexts.build(
            principal=principal, req=body.request, request_id="simulation", trace_id="0" * 31 + "1"
        )
        tool_name = payload.tool_call.name if payload.tool_call else None
        policy = await svc.policy.evaluate(built.policy_input(body.stage, tool_name))
        if not policy.allow:
            outcome = StageOutcome(Decision.BLOCK, f"policy denied: {policy.reason}", built.context.risk_score, None)
        else:
            engine = GuardrailEngine(
                default_timeout_ms=svc.settings.default_guardrail_timeout_ms, escalate_as_block=False
            )
            outcome = await engine.run(compiled, body.stage, built.context, payload, policy.obligations)
        released = outcome.payload if outcome.decision in (Decision.ALLOW, Decision.MODIFY) else None
        return JSONResponse(
            content={
                "simulated": True,
                "snapshot_version": compiled.version,
                "decision": outcome.decision.value,
                "reason": outcome.reason,
                "risk_score": max(built.context.risk_score, outcome.risk_score),
                "trust_score": built.context.trust_score,
                "policy": {"allow": policy.allow, "reason": policy.reason, "obligations": policy.obligations},
                "results": [r.model_dump(mode="json") for r in outcome.results],
                "payload": GuardPayloadIn.model_validate(released.model_dump(exclude={"stage"})).model_dump(mode="json")
                if released
                else None,
            }
        )
    finally:
        await compiled.close()
