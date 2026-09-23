"""Conformance suite: the automated MUST checks a guardrail passes before it can be registered.

Run locally with `guardrail conformance --manifest path/guardrail.yaml --config config.json`.
The control plane (phase 4) runs the same suite on POST /guardrails/{id}/versions.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError

from .guardrail import Guardrail
from .models import Chunk, Decision, GuardrailResult, Message, Payload, SecurityContext, Stage, ToolCall

MUST = "MUST"
SHOULD = "SHOULD"


@dataclass
class Check:
    name: str
    level: str
    passed: bool
    detail: str = ""


@dataclass
class Sample:
    payload: Payload
    sensitive_values: list[str] = field(default_factory=list)
    expect_decision: Decision | None = None


@dataclass
class ConformanceReport:
    guardrail: str
    checks: list[Check] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks if c.level == MUST)

    def add(self, name: str, level: str, passed: bool, detail: str = "") -> None:
        self.checks.append(Check(name, level, passed, detail))

    def to_dict(self) -> dict[str, Any]:
        return {
            "guardrail": self.guardrail,
            "passed": self.passed,
            "checks": [c.__dict__ for c in self.checks],
        }


def sample_context(stage: Stage) -> SecurityContext:
    return SecurityContext(
        request_id=f"conf-{uuid.uuid4()}",
        trace_id=uuid.uuid4().hex,
        tenant_id="conformance",
        agent_id="conformance-agent",
        user_id="user-1",
        session_id="sess-1",
        action="llm.chat" if stage in (Stage.INPUT, Stage.OUTPUT) else "database.read",
        resource="customer_db",
        trust_score=80,
        risk_score=20,
        data_classification="PII",
        environment="dev",
    )


def default_samples(stage: Stage) -> list[Sample]:
    pii = ["jane.doe@example.com", "+1 212 555 0199"]
    if stage in (Stage.INPUT, Stage.OUTPUT, Stage.AGENT):
        return [
            Sample(Payload(stage=stage, text="What is the capital of France?")),
            Sample(
                Payload(stage=stage, text=f"Email {pii[0]} or call {pii[1]} about the refund."),
                sensitive_values=pii,
            ),
            Sample(
                Payload(
                    stage=stage,
                    messages=[
                        Message(role="system", content="You are helpful."),
                        Message(role="user", content=f"My email is {pii[0]}"),
                    ],
                ),
                sensitive_values=pii[:1],
            ),
        ]
    if stage == Stage.RETRIEVAL:
        return [
            Sample(
                Payload(
                    stage=stage,
                    chunks=[
                        Chunk(id="c1", text="Quarterly revenue grew 12%."),
                        Chunk(id="c2", text=f"Contact {pii[0]} for access."),
                    ],
                ),
                sensitive_values=pii[:1],
            )
        ]
    if stage == Stage.TOOL:
        return [
            Sample(
                Payload(
                    stage=stage,
                    tool_call=ToolCall(
                        name="database.read",
                        arguments={"query": "select name from customers limit 1"},
                        result={"rows": [{"email": pii[0]}]},
                    ),
                ),
                sensitive_values=pii[:1],
            )
        ]
    return []


def _leaks(result: GuardrailResult, values: list[str]) -> list[str]:
    exposed = json.dumps(
        {
            "reason": result.reason,
            "findings": [f.model_dump() for f in result.findings],
            "metadata": result.metadata,
        },
        default=str,
    )
    return [v for v in values if v and v in exposed]


def _comparable(result: GuardrailResult) -> tuple[Any, ...]:
    mp = result.modified_payload.model_dump(mode="json") if result.modified_payload else None
    return (result.decision, json.dumps(mp, sort_keys=True))


async def run_conformance(
    guardrail: Guardrail,
    config: dict[str, Any],
    samples: dict[Stage, list[Sample]] | None = None,
) -> ConformanceReport:
    m = guardrail.manifest
    report = ConformanceReport(guardrail=m.key)

    # B6: config validated in setup(); unknown keys rejected.
    try:
        await guardrail.setup(config)
        report.add("setup accepts valid config", MUST, True)
    except (ValidationError, ValueError) as exc:
        report.add("setup accepts valid config", MUST, False, str(exc)[:300])
        return report
    try:
        await guardrail.setup({**config, "__not_a_real_option__": True})
        report.add("setup rejects unknown config keys", SHOULD, False, "unknown key accepted")
    except (ValidationError, ValueError):
        report.add("setup rejects unknown config keys", SHOULD, True)
    await guardrail.setup(config)

    # B7: health.
    try:
        healthy = await guardrail.health()
        report.add("health() returns True", MUST, bool(healthy), "" if healthy else "health() returned False")
    except Exception as exc:  # noqa: BLE001
        report.add("health() returns True", MUST, False, repr(exc)[:300])

    for stage in m.stages:
        for i, sample in enumerate((samples or {}).get(stage) or default_samples(stage)):
            label = f"{stage.value}[{i}]"
            ctx = sample_context(stage)
            ctx_before = ctx.model_dump()
            try:
                start = time.perf_counter()
                result = await guardrail.evaluate(ctx, sample.payload)
                elapsed = (time.perf_counter() - start) * 1000
            except Exception as exc:  # noqa: BLE001
                report.add(f"{label}: evaluate returns a result", MUST, False, repr(exc)[:300])
                continue
            report.add(f"{label}: evaluate returns a result", MUST, isinstance(result, GuardrailResult))
            if not isinstance(result, GuardrailResult):
                continue
            report.add(
                f"{label}: decision is declared in decisions_emitted",
                MUST,
                result.decision in m.decisions_emitted,
                result.decision.value,
            )
            if result.decision == Decision.MODIFY:
                assert result.modified_payload is not None
                report.add(
                    f"{label}: MODIFY keeps payload shape",
                    MUST,
                    sample.payload.same_shape_as(result.modified_payload),
                )
            report.add(f"{label}: context not mutated", MUST, ctx.model_dump() == ctx_before)
            leaked = _leaks(result, sample.sensitive_values)
            report.add(
                f"{label}: no raw sensitive values in reason/findings/metadata",
                MUST,
                not leaked,
                f"{len(leaked)} value(s) leaked" if leaked else "",
            )
            again = await guardrail.evaluate(sample_context(stage), sample.payload)
            report.add(f"{label}: deterministic", MUST, _comparable(again) == _comparable(result))
            report.add(
                f"{label}: within latency budget ({m.latency_budget_ms} ms)",
                SHOULD,
                elapsed <= m.latency_budget_ms,
                f"{elapsed:.1f} ms",
            )
            if sample.expect_decision is not None:
                report.add(
                    f"{label}: expected decision {sample.expect_decision.value}",
                    MUST,
                    result.decision == sample.expect_decision,
                    result.decision.value,
                )
    return report


class _SampleFile(BaseModel):
    stage: Stage
    payload: dict[str, Any]
    sensitive_values: list[str] = []
    expect_decision: Decision | None = None


def load_samples(path: str) -> dict[Stage, list[Sample]]:
    """JSON list of {stage, payload, sensitive_values?, expect_decision?}."""
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    out: dict[Stage, list[Sample]] = {}
    for item in raw:
        s = _SampleFile.model_validate(item)
        payload = Payload.model_validate({**s.payload, "stage": s.stage})
        out.setdefault(s.stage, []).append(Sample(payload, s.sensitive_values, s.expect_decision))
    return out
