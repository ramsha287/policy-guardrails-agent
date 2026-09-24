"""Dry-run a request through a draft snapshot (POST /internal/simulate, called by the control plane).

Runs the real plugins and OPA without enforcing, auditing or filing reviews. The snapshot may be
for another environment than this gateway's (a production draft simulated on a dev gateway):
scoring and the OPA input then use the snapshot's environment, while plugins use this
gateway's endpoints and secrets. The result reports both environments.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ValidationError

from app.context.builder import ContextBuilder
from app.context.catalog import CachedCatalog
from app.engine.pipeline import GuardrailEngine, StageOutcome
from app.engine.remote import CatalogHolder
from app.engine.snapshot import parse_snapshot
from app.gateway.auth import Principal
from app.gateway.normalize import normalize_payload
from guardrail_sdk import Decision, GuardPayloadIn, GuardRequest, Payload, Stage

if TYPE_CHECKING:  # app.services pulls in the database layer
    from app.services import Services


class SimulateIn(BaseModel):
    snapshot: dict[str, Any]
    catalog: dict[str, Any] | None = None
    tenant_id: str
    stage: Stage
    request: GuardRequest


class SimulationError(Exception):
    def __init__(self, status: int, error: str) -> None:
        super().__init__(error)
        self.status = status
        self.error = error


async def simulate(svc: Services, body: SimulateIn) -> dict[str, Any]:
    if svc.registry is None:
        raise SimulationError(503, "simulation is not available on this gateway")
    try:
        doc = parse_snapshot(body.snapshot)
    except Exception as exc:  # noqa: BLE001 - e.g. a ${VAR} this gateway lacks
        raise SimulationError(422, f"snapshot is invalid here: {exc.__class__.__name__}: {exc}") from exc
    env = doc.environment
    try:
        compiled = await svc.registry.compile(doc, env)
    except Exception as exc:  # noqa: BLE001
        raise SimulationError(422, f"snapshot does not compile on this gateway: {exc}") from exc
    try:
        contexts = svc.contexts.for_environment(env)
        if body.catalog is not None:
            holder = CatalogHolder(env)
            if not holder.apply(body.catalog):
                raise SimulationError(422, f"invalid catalog document: {holder.last_error}")
            contexts = ContextBuilder(CachedCatalog(holder, ttl_seconds=0), env)
        try:
            payload = normalize_payload(Payload(stage=body.stage, **body.request.payload.model_dump()))
        except ValidationError as exc:
            raise SimulationError(422, f"invalid payload: {exc.errors()[0]['msg']}") from exc
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
        return {
            "simulated": True,
            "environment": env,
            "simulated_on": svc.settings.environment,
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
    finally:
        await compiled.close()
