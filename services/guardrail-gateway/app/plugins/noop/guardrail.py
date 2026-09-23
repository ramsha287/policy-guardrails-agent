from __future__ import annotations

from guardrail_sdk import Decision, Guardrail, GuardrailResult, Payload, SecurityContext


class NoopGuardrail(Guardrail):
    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        return GuardrailResult(decision=Decision.ALLOW, reason="noop", risk_score=0)
