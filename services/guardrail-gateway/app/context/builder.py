"""Context Builder: turns an authenticated request into a SecurityContext.

Scores are kept separate (both go to OPA, neither is blended into the other):
- trust_score = the agent's base trust from agent_profiles (unknown agent -> 0)
- risk_score  = min(100, action base risk + classification modifier + environment modifier)
                (unknown action -> 100)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.context.catalog import AgentInfo, CachedCatalog
from app.gateway.auth import Principal
from guardrail_sdk import GuardRequest, SecurityContext, Stage

UNKNOWN_AGENT_TRUST = 0
UNKNOWN_ACTION_RISK = 100


@dataclass(frozen=True)
class BuiltContext:
    context: SecurityContext
    agent: AgentInfo | None
    action_known: bool

    def policy_input(self, stage: Stage, tool_name: str | None) -> dict[str, Any]:
        """The document OPA evaluates. Payload text is never sent to OPA."""
        return {
            "stage": stage.value,
            "context": self.context.model_dump(mode="json", exclude={"arguments"}),
            "agent": {
                "known": self.agent is not None,
                "allowed_tools": list(self.agent.allowed_tools) if self.agent else [],
            },
            "action_known": self.action_known,
            "tool_name": tool_name,
        }


class ContextBuilder:
    def __init__(self, catalog: CachedCatalog, environment: str) -> None:
        self._catalog = catalog
        self._env = environment

    async def build(self, *, principal: Principal, req: GuardRequest, request_id: str, trace_id: str) -> BuiltContext:
        cat = await self._catalog.get(principal.tenant_id)
        agent = cat.agent(req.agent_id)
        trust = agent.base_trust_score if agent else UNKNOWN_AGENT_TRUST

        rule = cat.action_rule(req.action, req.resource)
        if rule is None:
            risk = UNKNOWN_ACTION_RISK
        else:
            risk = (
                rule.base_risk_score
                + cat.modifier("classification", req.data_classification)
                + cat.modifier("environment", self._env)
            )
        risk = max(0, min(100, risk))

        ctx = SecurityContext(
            request_id=request_id,
            trace_id=trace_id,
            tenant_id=principal.tenant_id,
            agent_id=req.agent_id,
            user_id=req.user_id,
            session_id=req.session_id,
            action=req.action,
            resource=req.resource,
            arguments=req.arguments,
            trust_score=trust,
            risk_score=risk,
            data_classification=req.data_classification,
            environment=self._env,  # type: ignore[arg-type]
            delegation_chain=req.delegation_chain,
            tool_metadata=req.tool_metadata,
        )
        return BuiltContext(ctx, agent, rule is not None)
