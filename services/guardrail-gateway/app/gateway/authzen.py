"""OpenID AuthZEN Authorization API 1.0 mapping for tool calls (the gateway as a PDP).

A policy enforcement point (an API gateway, an MCP server, a service mesh filter) that speaks
AuthZEN can ask the guardrail gateway "may this agent do this?" without our SDK:

    POST /access/v1/evaluation
    {"subject":  {"type": "agent", "id": "research-agent", "properties": {"user_id": "u1", "session_id": "s1"}},
     "action":   {"name": "db.query"},
     "resource": {"type": "database", "id": "analytics", "properties": {"arguments": {"sql": "SELECT ..."}}},
     "context":  {"data_classification": "PII", "accepts_obligations": true}}

    -> {"decision": true, "context": {"outcome": "allow", "reason_codes": [...], "decision_id": "...", ...}}

It runs exactly the same pipeline as POST /v1/guard/tool (identity binding, OPA, guardrails,
risk, decision table, verification, audit). `decision` is a plain yes/no, so it is true only when
the PEP may go ahead as asked:

    allow                        true
    allow_restricted             true, with context.obligations (only if context.accepts_obligations)
    modify (e.g. redaction)      true with context.modified_arguments if context.accepts_modifications,
                                 otherwise false ("MODIFY_UNSUPPORTED_BY_PEP"): the PEP would send the
                                 unredacted original
    verify / hold                false, with context.verification or context.escalation_id
    deny / quarantine_session    false
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from guardrail_sdk import Decision, GuardRequest, GuardResponse

MAX_BATCH = 50
SEMANTICS = ("execute_all", "deny_on_first_deny", "permit_on_first_permit")


class Entity(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str = Field(default="", max_length=128)
    id: str = Field(default="", max_length=256)
    properties: dict[str, Any] = Field(default_factory=dict)


class ActionIn(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str = Field(min_length=1, max_length=128)
    properties: dict[str, Any] = Field(default_factory=dict)


class EvaluationIn(BaseModel):
    model_config = ConfigDict(extra="allow")
    subject: Entity | None = None
    action: ActionIn | None = None
    resource: Entity | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class EvaluationsIn(EvaluationIn):
    evaluations: list[EvaluationIn] = Field(default_factory=list, max_length=MAX_BATCH)
    options: dict[str, Any] = Field(default_factory=dict)


class MappingError(ValueError):
    pass


def merge(defaults: EvaluationIn, item: EvaluationIn) -> EvaluationIn:
    """Batch semantics: each evaluation's subject/action/resource/context override the top-level ones."""
    return EvaluationIn(
        subject=item.subject or defaults.subject,
        action=item.action or defaults.action,
        resource=item.resource or defaults.resource,
        context={**defaults.context, **item.context},
    )


def _pick(name: str, *sources: dict[str, Any]) -> Any:
    for s in sources:
        if name in s and s[name] is not None:
            return s[name]
    return None


def to_guard_request(ev: EvaluationIn) -> GuardRequest:
    if ev.subject is None or not ev.subject.id:
        raise MappingError("subject.id (the agent id) is required")
    if ev.action is None:
        raise MappingError("action.name is required")
    subj, res, ctx = ev.subject.properties, (ev.resource.properties if ev.resource else {}), ev.context
    arguments = _pick("arguments", res, ctx, ev.action.properties) or {}
    if not isinstance(arguments, dict):
        raise MappingError("arguments must be an object")
    resource_id = None
    if ev.resource is not None and (ev.resource.id or ev.resource.type):
        resource_id = ev.resource.id or ev.resource.type
    body: dict[str, Any] = {
        "agent_id": ev.subject.id,
        "action": ev.action.name,
        "resource": resource_id,
        "user_id": _pick("user_id", subj, ctx),
        "session_id": _pick("session_id", subj, ctx),
        "arguments": {},
        "data_classification": _pick("data_classification", ctx, res) or "INTERNAL",
        "delegation_chain": _pick("delegation_chain", subj, ctx) or [],
        "tool_metadata": _pick("tool_metadata", ctx, res),
        "accepts_obligations": bool(ctx.get("accepts_obligations")) or None,
        "verification_channels": ctx.get("verification_channels"),
        "payload": {"tool_call": {"name": ev.action.name, "arguments": arguments}},
    }
    try:
        return GuardRequest.model_validate({k: v for k, v in body.items() if v is not None})
    except ValidationError as exc:
        err = exc.errors()[0]
        raise MappingError(f"{'.'.join(str(p) for p in err.get('loc', []))}: {err.get('msg')}") from exc


def to_authzen(resp: GuardResponse, *, accepts_modifications: bool) -> dict[str, Any]:
    outcome = resp.outcome or resp.decision.value
    codes = list(resp.reason_codes)
    ctx: dict[str, Any] = {
        "decision_id": resp.request_id,
        "outcome": outcome,
        "reason": resp.reason,
        "reason_codes": codes,
        "assurance": resp.assurance,
    }
    if resp.risk is not None:
        ctx["risk"] = {"score": resp.risk.score, "band": resp.risk.band, "mode": resp.risk.mode}
    if resp.obligations:
        ctx["obligations"] = resp.obligations
    if resp.verification is not None:
        ctx["verification"] = resp.verification.model_dump(mode="json")
    if resp.escalation_id:
        ctx["escalation_id"] = resp.escalation_id

    allowed = resp.decision in (Decision.ALLOW, Decision.MODIFY)
    if resp.decision == Decision.MODIFY:
        if accepts_modifications and resp.payload is not None and resp.payload.tool_call is not None:
            ctx["modified_arguments"] = resp.payload.tool_call.arguments
        else:
            allowed = False
            ctx["reason_codes"] = [*codes, "MODIFY_UNSUPPORTED_BY_PEP"]
    return {"decision": allowed, "context": ctx}


def denied(reason: str, code: str) -> dict[str, Any]:
    return {"decision": False, "context": {"outcome": "deny", "reason": reason, "reason_codes": [code]}}


def configuration(base_url: str) -> dict[str, Any]:
    base = base_url.rstrip("/")
    return {
        "policy_decision_point": base,
        "access_evaluation_endpoint": f"{base}/access/v1/evaluation",
        "access_evaluations_endpoint": f"{base}/access/v1/evaluations",
    }
