"""Precision/recall evaluation of a guardrail against a labelled dataset (plugin requirement D).

Dataset: JSON Lines, one case per line:
    {"id": "input-0001", "stage": "input", "label": "pii" | "clean", "payload": {...}, "entities": ["EMAIL_ADDRESS"]}

A case counts as *detected* when the guardrail returns MODIFY or BLOCK, or reports findings.
Metrics are computed per stage and overall; latency p50/p95 is measured per call.

    guardrail evaluate --manifest guardrail.yaml --config config.json --dataset eval/datasets/pii.jsonl \
        --min-precision 0.9 --min-recall 0.9 --report report.json
"""

from __future__ import annotations

import json
import statistics
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .guardrail import Guardrail
from .models import Decision, Payload, SecurityContext, Stage


@dataclass
class Case:
    id: str
    stage: Stage
    label: bool  # True = contains PII (should be detected)
    payload: Payload
    entities: list[str] = field(default_factory=list)


@dataclass
class StageMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    errors: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    misses: list[str] = field(default_factory=list)  # ids of false negatives
    false_alarms: list[str] = field(default_factory=list)  # ids of false positives
    error_ids: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def percentile(self, q: float) -> float:
        if not self.latencies_ms:
            return 0.0
        data = sorted(self.latencies_ms)
        return data[min(len(data) - 1, int(round(q * (len(data) - 1))))]

    def add(self, other: StageMetrics) -> None:
        self.tp += other.tp
        self.fp += other.fp
        self.fn += other.fn
        self.tn += other.tn
        self.errors += other.errors
        self.latencies_ms += other.latencies_ms

    def to_dict(self) -> dict[str, Any]:
        return {
            "cases": self.total,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "errors": self.errors,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "latency_p50_ms": round(self.percentile(0.5), 1),
            "latency_p95_ms": round(self.percentile(0.95), 1),
            "mean_latency_ms": round(statistics.fmean(self.latencies_ms), 1) if self.latencies_ms else 0.0,
            "false_negatives": self.misses[:50],
            "false_positives": self.false_alarms[:50],
            "error_cases": self.error_ids[:50],
        }


def load_dataset(path: str | Path) -> list[Case]:
    cases = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        raw = json.loads(line)
        stage = Stage(raw["stage"])
        if raw["label"] not in ("pii", "clean"):
            raise ValueError(f"line {n}: label must be 'pii' or 'clean'")
        cases.append(
            Case(
                id=raw.get("id") or f"case-{n}",
                stage=stage,
                label=raw["label"] == "pii",
                payload=Payload.model_validate({**raw["payload"], "stage": stage}),
                entities=list(raw.get("entities") or []),
            )
        )
    return cases


def _context(stage: Stage) -> SecurityContext:
    return SecurityContext(
        request_id=f"eval-{uuid.uuid4()}",
        trace_id=uuid.uuid4().hex,
        tenant_id="evaluation",
        agent_id="evaluation-agent",
        action="llm.chat" if stage in (Stage.INPUT, Stage.OUTPUT) else "evaluation",
        trust_score=80,
        risk_score=20,
        data_classification="PII",
        environment="dev",
    )


async def evaluate(guardrail: Guardrail, cases: list[Case]) -> dict[str, StageMetrics]:
    per_stage: dict[str, StageMetrics] = {}
    for case in cases:
        if case.stage not in guardrail.stages:
            continue
        m = per_stage.setdefault(case.stage.value, StageMetrics())
        started = time.perf_counter()
        try:
            result = await guardrail.evaluate(_context(case.stage), case.payload)
        except Exception:  # noqa: BLE001 - an error is neither a detection nor a pass; reported separately
            m.errors += 1
            m.error_ids.append(case.id)
            continue
        m.latencies_ms.append((time.perf_counter() - started) * 1000)
        detected = result.decision in (Decision.MODIFY, Decision.BLOCK) or bool(result.findings)
        if case.label and detected:
            m.tp += 1
        elif case.label:
            m.fn += 1
            m.misses.append(case.id)
        elif detected:
            m.fp += 1
            m.false_alarms.append(case.id)
        else:
            m.tn += 1
    return per_stage


def report(per_stage: dict[str, StageMetrics], guardrail_key: str) -> dict[str, Any]:
    overall = StageMetrics()
    for m in per_stage.values():
        overall.add(m)
    return {
        "guardrail": guardrail_key,
        "stages": {s: m.to_dict() for s, m in sorted(per_stage.items())},
        "overall": {
            k: v for k, v in overall.to_dict().items() if k not in ("false_negatives", "false_positives", "error_cases")
        },
    }


def meets(per_stage: dict[str, StageMetrics], min_precision: float, min_recall: float, min_cases: int) -> list[str]:
    """Return the list of threshold violations (empty = pass)."""
    problems = []
    for stage, m in sorted(per_stage.items()):
        if m.errors:
            problems.append(f"{stage}: {m.errors} case(s) raised errors")
        if m.total < min_cases:
            problems.append(f"{stage}: {m.total} cases < required {min_cases}")
        if m.precision < min_precision:
            problems.append(f"{stage}: precision {m.precision:.3f} < {min_precision}")
        if m.recall < min_recall:
            problems.append(f"{stage}: recall {m.recall:.3f} < {min_recall}")
    return problems
