"""`local`: a small logistic classifier over the question's features. Runs in-process, no network.

The weights are a JSON file (default: app/advise/models/local-v1.json), trained offline from the
red-team harness's labelled actions with `python -m eval.redteam train-local` and committed with
the evaluation that justified them. Swap the file to retrain; the gateway never learns online.

    {"version": "local-v1",
     "questions": {"exfiltration": {"bias": -3.1, "weights": {"dest_external": 1.9, ...},
                                    "suspicious_at": 0.5, "malicious_at": 0.8, "verify_at": 0.9}, ...}}
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.advise.contract import Answer, Features, Question

DEFAULT_WEIGHTS = Path(__file__).resolve().parent.parent / "models" / "local-v1.json"

VERBS = ("read", "write", "send", "delete", "execute", "admin", "unknown")
KINDS = ("sql", "http", "file", "message", "model", "unknown")


def vectorize(f: Features) -> dict[str, float]:
    """Features -> named numbers in [0, 1]. Shared by the provider and the trainer."""
    labels = set(f.session_labels)
    codes = set(f.risk_codes)
    v: dict[str, float] = {f"verb_{x}": float(f.verb == x) for x in VERBS}
    v.update({f"kind_{x}": float(f.kind == x) for x in KINDS})
    v.update(
        stage_tool=float(f.stage == "tool"),
        is_tool_result=float(f.is_tool_result),
        unparsed=float(not f.parsed),
        dest_external=float(f.destination == "external"),
        dest_internal=float(f.destination == "internal"),
        host_is_ip=float(f.host_is_ip),
        host_deep=min(1.0, max(0, f.host_labels - 2) / 3),
        host_lookalike=float(f.host_lookalike_internal),
        first_seen=float(bool(f.first_seen_target)),
        tainted=float("untrusted_input" in labels),
        holds_sensitive=float(bool(labels & {"holds:PII", "holds:CONFIDENTIAL"})),
        class_sensitive=float(f.data_classification in ("PII", "CONFIDENTIAL")),
        production=float(f.environment == "production"),
        low_assurance=float(f.assurance == "A0"),
        steps=min(1.0, f.session_steps / 20),
        denials=min(1.0, f.session_denials / 5),
        young_session=float(f.session_age_seconds < 300),
        risk=f.risk_score / 100,
        trust=f.trust / 100,
        low_confidence=1.0 - f.confidence,
        payload_size=min(1.0, math.log1p(f.payload_bytes) / math.log1p(1_000_000)),
        urls=min(1.0, f.url_count / 5),
        emails=min(1.0, f.email_count / 5),
        ip_literals=min(1.0, f.ip_literal_count / 3),
        encoded_blob=float(f.encoded_blob),
        query_payload=min(1.0, math.log1p(f.url_query_bytes) / math.log1p(4096)),
        findings=min(1.0, len(f.finding_types) / 3),
        finding_score=f.max_finding_score,
        guardrail_flagged=float(bool(f.guardrail_flags)),
        rows=0.0 if f.rows_requested is None else min(1.0, math.log1p(f.rows_requested) / math.log1p(100_000)),
        unbounded=float(f.kind == "sql" and f.rows_requested is None and f.has_filter is False),
        multi_statement=float(f.statements > 1),
        sensitive_then_external=float("SENSITIVE_THEN_EXTERNAL" in codes),
        new_resource=float("NEW_RESOURCE" in codes),
    )
    return v


class QuestionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bias: float
    weights: dict[str, float]
    suspicious_at: float = Field(0.5, gt=0, lt=1)
    malicious_at: float = Field(0.8, gt=0, lt=1)
    verify_at: float = Field(1.0, gt=0, le=1)  # 1.0 = never asks for verification


class LocalModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    questions: dict[str, QuestionModel]
    trained_on: dict[str, Any] = Field(default_factory=dict)

    def probability(self, kind: str, f: Features) -> float | None:
        m = self.questions.get(kind)
        if m is None:
            return None
        x = vectorize(f)
        z = m.bias + sum(w * x.get(name, 0.0) for name, w in m.weights.items())
        return 1 / (1 + math.exp(-max(-40.0, min(40.0, z))))


def load_model(path: str | Path | None = None) -> LocalModel:
    raw = json.loads(Path(path or DEFAULT_WEIGHTS).read_text(encoding="utf-8"))
    return LocalModel.model_validate(raw)


class LocalAdvisor:
    hosted = False

    def __init__(self, name: str, model: LocalModel) -> None:
        self.name = name
        self.model = model

    @classmethod
    def from_options(cls, name: str, options: dict[str, Any]) -> LocalAdvisor:
        unknown = set(options) - {"weights_path"}
        if unknown:
            raise ValueError(f"local advisor {name}: unknown option(s) {sorted(unknown)}")
        return cls(name, load_model(options.get("weights_path")))

    async def ask(self, question: Question) -> Answer:
        p = self.model.probability(question.kind, question.features)
        if p is None:
            raise LookupError(f"model {self.model.version} has no {question.kind} question")
        m = self.model.questions[question.kind]
        if p >= m.malicious_at:
            return Answer(label="malicious", confidence=round(p, 4), verify=p >= m.verify_at)
        if p >= m.suspicious_at:
            return Answer(label="suspicious", confidence=round(p, 4), verify=p >= m.verify_at)
        return Answer(label="benign", confidence=round(1 - p, 4))

    async def close(self) -> None:
        return None
