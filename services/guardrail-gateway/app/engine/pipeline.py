"""Guardrail Engine: run a stage's guardrails and aggregate one decision.

Rules (plan section 4):
- guardrails run in `order`; consecutive assignments sharing a `parallel_group` run together;
- MODIFY chains: the next guardrail sees the modified payload;
- BLOCK short-circuits the rest of the stage;
- strongest decision wins: BLOCK > ESCALATE > MODIFY > ALLOW;
- errors and time-outs follow the assignment's failure mode (fail_closed -> BLOCK);
- `shadow` assignments run and are recorded but never change the outcome;
- ESCALATE holds the request for human review when a review queue is configured
  (CONFIG_SOURCE=control_plane); without one it becomes BLOCK, so nothing slips through.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from app.engine.registry import BoundGuardrail, CompiledSnapshot
from app.observability import DECISIONS, GUARDRAIL_ERRORS, GUARDRAIL_LATENCY, span
from guardrail_sdk import (
    Decision,
    GuardrailOutcome,
    GuardrailResult,
    Payload,
    SecurityContext,
    Stage,
    strongest,
)


@dataclass
class StageOutcome:
    decision: Decision
    reason: str
    risk_score: int
    payload: Payload | None
    results: list[GuardrailOutcome] = field(default_factory=list)


class GuardrailEngine:
    def __init__(self, default_timeout_ms: int = 1000, escalate_as_block: bool = True) -> None:
        self._default_timeout_ms = default_timeout_ms
        self._escalate_as_block = escalate_as_block

    @staticmethod
    def _groups(bound: list[BoundGuardrail]) -> list[list[BoundGuardrail]]:
        groups: list[list[BoundGuardrail]] = []
        for b in bound:
            g = b.assignment.parallel_group
            if g and groups and groups[-1][0].assignment.parallel_group == g:
                groups[-1].append(b)
            else:
                groups.append([b])
        return groups

    async def _call(
        self, b: BoundGuardrail, stage: Stage, ctx: SecurityContext, payload: Payload
    ) -> tuple[GuardrailOutcome, GuardrailResult]:
        gid, mode = b.manifest.id, b.assignment.mode
        timeout_s = b.timeout_ms(self._default_timeout_ms) / 1000
        error: str | None = None
        started = time.perf_counter()
        with span(f"guardrail.{gid}.evaluate", stage=stage.value, guardrail_version=b.manifest.version, mode=mode) as s:
            try:
                result = await asyncio.wait_for(b.guardrail.evaluate(ctx, payload), timeout=timeout_s)
                if result.decision not in b.manifest.decisions_emitted:
                    error = f"undeclared decision {result.decision.value}"
                elif result.decision == Decision.MODIFY and not payload.same_shape_as(result.modified_payload):  # type: ignore[arg-type]
                    error = "MODIFY changed the payload shape"
            except TimeoutError:
                error = "timeout"
            except Exception as exc:  # noqa: BLE001 - any plugin failure goes through the failure policy
                error = exc.__class__.__name__
            latency = (time.perf_counter() - started) * 1000

            if error is not None:
                GUARDRAIL_ERRORS.labels(gid, stage.value, "timeout" if error == "timeout" else "error").inc()
                closed = b.failure_mode == "fail_closed"
                result = GuardrailResult(
                    decision=Decision.BLOCK if closed else Decision.ALLOW,
                    reason=f"guardrail {gid} failed ({error}); {b.failure_mode}",
                    risk_score=100 if closed else 0,
                )
            result.latency_ms = round(latency, 2)
            if s is not None:
                s.set_attribute("decision", result.decision.value)
                s.set_attribute("latency_ms", result.latency_ms)

        DECISIONS.labels(gid, stage.value, result.decision.value, mode).inc()
        GUARDRAIL_LATENCY.labels(gid, stage.value).observe(latency)
        outcome = GuardrailOutcome(
            guardrail_id=gid,
            version=b.manifest.version,
            decision=result.decision,
            reason=result.reason,
            risk_score=result.risk_score,
            latency_ms=result.latency_ms,
            mode=mode,
            error=error,
            findings=result.findings,
        )
        return outcome, result

    async def run(
        self,
        snapshot: CompiledSnapshot,
        stage: Stage,
        ctx: SecurityContext,
        payload: Payload,
        obligations: list[str] | None = None,
    ) -> StageOutcome:
        bound = snapshot.resolve(ctx.tenant_id, ctx.agent_id, stage)

        enforced_ids = {b.manifest.id for b in bound if b.assignment.mode == "enforce"}
        missing = [o for o in (obligations or []) if o not in enforced_ids]
        if missing:
            return StageOutcome(
                Decision.BLOCK,
                f"policy requires {', '.join(missing)} at stage {stage.value} but it is not enforced (fail-closed)",
                100,
                None,
            )

        current = payload
        outcomes: list[GuardrailOutcome] = []
        decisions: list[Decision] = []
        risk = 0
        deciding_reason: dict[Decision, str] = {}
        stop = False

        for group in self._groups(bound):
            if len(group) == 1:
                results = [await self._call(group[0], stage, ctx, current)]
            else:
                results = list(await asyncio.gather(*(self._call(b, stage, ctx, current) for b in group)))
            for b, (outcome, result) in zip(group, results, strict=True):
                outcomes.append(outcome)
                if b.assignment.mode == "shadow":
                    continue
                decisions.append(result.decision)
                risk = max(risk, result.risk_score)
                deciding_reason.setdefault(result.decision, f"{b.manifest.id}: {result.reason}")
                if result.decision == Decision.MODIFY and result.modified_payload is not None:
                    current = result.modified_payload
                if result.decision in (Decision.BLOCK, Decision.ESCALATE):
                    stop = True
            if stop:
                break

        final = strongest(decisions)
        if not bound:
            reason = f"no guardrails assigned for stage {stage.value}"
        elif final == Decision.ALLOW:
            reason = "all guardrails allowed the request"
        else:
            reason = deciding_reason[final]

        if final == Decision.ESCALATE and self._escalate_as_block:
            final = Decision.BLOCK
            reason = f"{reason} (escalation required; human review queue not yet available, blocking)"

        return StageOutcome(
            decision=final,
            reason=reason,
            risk_score=risk,
            # ESCALATE keeps the payload so it can be *held* for review; the API never returns it.
            payload=None if final == Decision.BLOCK else current,
            results=outcomes,
        )
