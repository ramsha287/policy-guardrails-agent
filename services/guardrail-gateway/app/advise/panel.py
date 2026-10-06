"""The advisor panel: when advisors run, how their answers count, and what is recorded.

Rules (design doc section 11), enforced here rather than trusted to each provider:

1. Only in the uncertain band. Advisors run for `elevated` and `high` risk (configurable). Low risk
   doesn't need them; critical risk goes to a person anyway. This bounds cost and attack surface.
2. Only tighten. An enforcing advisor adds at most `cap` points (and all of them together at most
   `total_cap`, 20 by default) or asks for verification. A benign answer adds nothing; it never
   removes anything.
3. Timeouts and failures are no signal. The deterministic path decides exactly as without advisors.
4. Tenant data policy. A hosted advisor (the question leaves the gateway) runs only when the tenant
   opted in for the request's data class and for every sensitive label its session holds.
   Off by default.
5. Shadow first. `mode: shadow` records the answer with the decision and changes nothing; that is
   how a new advisor (the Jev pilot, an LLM judge) is measured before it is trusted.

The agent never sees advisor answers: the response carries only an aggregated `ADVISOR_RISK`
signal when enforcing advisors added points. Per-advisor answers go to the audit record.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.advise.contract import QUESTIONS, Advisor, Answer, Features, Question, QuestionKind, points_for
from app.observability import ADVISOR_ANSWERS, ADVISOR_LATENCY

logger = logging.getLogger(__name__)

DATA_CLASSES = ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII")
Status = Literal["answered", "timeout", "error", "invalid", "skipped_policy"]


class AdvisorSpec(BaseModel):
    """One configured advisor (an entry of ADVISORS_JSON)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,39}$")
    provider: Literal["local", "http", "bedrock"]
    mode: Literal["shadow", "enforce"] = "shadow"
    questions: list[QuestionKind] = Field(default_factory=lambda: list(QUESTIONS))
    cap: int = Field(10, ge=0, le=20)  # points this advisor can add
    timeout_ms: int = Field(200, ge=10, le=15_000)
    allow_verify: bool = True  # may ask for verification (in addition to points)
    options: dict[str, Any] = Field(default_factory=dict)  # provider settings (url, model, weights ...)

    @field_validator("questions")
    @classmethod
    def _questions(cls, v: list[QuestionKind]) -> list[QuestionKind]:
        if not v:
            raise ValueError("an advisor needs at least one question")
        return list(dict.fromkeys(v))


class PanelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    advisors: list[AdvisorSpec] = Field(default_factory=list)
    total_cap: int = Field(20, ge=0, le=40)
    bands: list[Literal["low", "elevated", "high", "critical"]] = Field(default_factory=lambda: ["elevated", "high"])

    @field_validator("advisors")
    @classmethod
    def _unique(cls, v: list[AdvisorSpec]) -> list[AdvisorSpec]:
        names = [a.name for a in v]
        if len(names) != len(set(names)):
            raise ValueError("advisor names must be unique")
        return v


@dataclass(frozen=True)
class AdvisorRecord:
    """One answer (or non-answer), as audited. Never contains the question's content."""

    advisor: str
    provider: str
    mode: str
    question: str
    status: Status
    latency_ms: float = 0.0
    label: str | None = None
    confidence: float | None = None
    points: int = 0  # what this answer is worth (counted only when mode == enforce)
    verify: bool = False
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "advisor": self.advisor,
            "provider": self.provider,
            "mode": self.mode,
            "question": self.question,
            "status": self.status,
            "latency_ms": self.latency_ms,
        }
        if self.status == "answered":
            out.update(label=self.label, confidence=self.confidence, points=self.points, verify=self.verify)
        if self.detail:
            out["detail"] = self.detail[:200]
        return out


@dataclass(frozen=True)
class Advisory:
    """The panel's combined result for one request."""

    points: int = 0  # enforced, after the caps
    verify: bool = False  # enforced
    shadow_points: int = 0  # what shadow advisors would have added (same caps)
    shadow_verify: bool = False
    records: tuple[AdvisorRecord, ...] = field(default_factory=tuple)
    # The question's features (derived only: counts, shapes, codes - never text). Audited so
    # reviewers' decisions can later label them to calibrate advisors (app/advise/calibrate.py).
    features: Features | None = None

    @property
    def ran(self) -> bool:
        return bool(self.records)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "points": self.points,
            "verify": self.verify,
            "shadow_points": self.shadow_points,
            "shadow_verify": self.shadow_verify,
            "answers": [r.to_dict() for r in self.records],
        }
        if self.features is not None:
            out["features"] = self.features.model_dump(mode="json")
        return out


SENSITIVE_LABELS = {"holds:PII": "PII", "holds:CONFIDENTIAL": "CONFIDENTIAL"}


def hosted_allowed(features: Features, allowed_classes: frozenset[str]) -> bool:
    """A hosted advisor may see this request only if the tenant opted in for its data class and for
    every sensitive data class the session already holds."""
    needed = {features.data_classification} | {
        SENSITIVE_LABELS[x] for x in features.session_labels if x in SENSITIVE_LABELS
    }
    return needed <= allowed_classes


class AdvisorPanel:
    def __init__(
        self,
        config: PanelConfig,
        advisors: dict[str, Advisor],
        *,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        missing = {a.name for a in config.advisors} - set(advisors)
        if missing:
            raise ValueError(f"no provider instance for advisor(s) {sorted(missing)}")
        self.config = config
        self.advisors = advisors
        self._clock = clock

    @property
    def specs(self) -> Sequence[AdvisorSpec]:
        return self.config.advisors

    def applies(self, band: str) -> bool:
        return bool(self.config.advisors) and band in self.config.bands

    async def advise(
        self, *, tenant_id: str, agent_id: str, features: Features, hosted_classes: frozenset[str]
    ) -> Advisory:
        if not self.applies(features.risk_band):
            return Advisory()
        jobs = []
        skipped: list[AdvisorRecord] = []
        for spec in self.config.advisors:
            advisor = self.advisors[spec.name]
            for kind in spec.questions:
                if advisor.hosted and not hosted_allowed(features, hosted_classes):
                    skipped.append(AdvisorRecord(spec.name, spec.provider, spec.mode, kind, "skipped_policy"))
                    continue
                q = Question(kind=kind, tenant_id=tenant_id, agent_id=agent_id, features=features)
                jobs.append(self._ask(spec, advisor, q))
        answered = list(await asyncio.gather(*jobs)) if jobs else []
        records = tuple(answered + skipped)
        for r in records:
            ADVISOR_ANSWERS.labels(r.advisor, r.mode, r.status, r.label or "none").inc()
        return replace(combine(records, self.config), features=features)

    async def _ask(self, spec: AdvisorSpec, advisor: Advisor, q: Question) -> AdvisorRecord:
        started = self._clock()

        def rec(status: Status, **kw: Any) -> AdvisorRecord:
            ms = round((self._clock() - started) * 1000, 2)
            ADVISOR_LATENCY.labels(spec.name).observe(ms)
            return AdvisorRecord(spec.name, spec.provider, spec.mode, q.kind, status, latency_ms=ms, **kw)

        try:
            raw = await asyncio.wait_for(advisor.ask(q), timeout=spec.timeout_ms / 1000)
        except TimeoutError:
            return rec("timeout")
        except Exception as exc:  # noqa: BLE001 - an advisor failure is no signal, never an error
            logger.warning("advisor %s failed: %s", spec.name, exc.__class__.__name__)
            return rec("error", detail=exc.__class__.__name__)
        try:
            answer = raw if isinstance(raw, Answer) else Answer.model_validate(raw)
        except (ValidationError, TypeError, ValueError) as exc:
            return rec("invalid", detail=exc.__class__.__name__)
        verify = answer.verify and spec.allow_verify and answer.label != "benign"
        return rec(
            "answered",
            label=answer.label,
            confidence=round(answer.confidence, 4),
            points=points_for(answer, spec.cap),
            verify=verify,
        )

    async def close(self) -> None:
        for a in self.advisors.values():
            try:
                await a.close()
            except Exception:  # noqa: BLE001
                logger.warning("advisor %s did not close cleanly", a.name)


def combine(records: Sequence[AdvisorRecord], config: PanelConfig) -> Advisory:
    """Per advisor: the highest answer across its questions; then the total cap. Shadow and enforce
    are added up separately, so shadow advisors show what they *would* have done."""

    def total(mode: str) -> tuple[int, bool]:
        best: dict[str, int] = {}
        verify = False
        for r in records:
            if r.mode != mode or r.status != "answered":
                continue
            best[r.advisor] = max(best.get(r.advisor, 0), r.points)
            verify = verify or r.verify
        return min(config.total_cap, sum(best.values())), verify

    points, verify = total("enforce")
    shadow_points, shadow_verify = total("shadow")
    return Advisory(points, verify, shadow_points, shadow_verify, tuple(records))
