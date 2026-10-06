"""Risk v2: an additive, capped, reason-coded score, with dynamic trust.

    risk = min(100, inherent + sum(min(cap_k, signal_k)) + confidence penalty)

`inherent` is the phase-1 score (action base risk + classification and environment modifiers).
Each signal has a name (its reason code), a few points and a cap, so a decision can always be
explained by listing the codes. No signal can lower the score.

Trust is per agent: the approved base trust from the catalog, minus trust penalties that fade
with a half-life. Behaviour never raises trust above the approved base (no reward term), so an
attacker can't "bank" trust with a long run of harmless calls.

The band thresholds move with trust: a trusted agent may do a bit more before it is asked for
evidence, but nothing at or above 80 is ever "low risk".
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field

from app.context.descriptors import ActionDescriptor
from app.session.store import SessionView

Band = Literal["low", "elevated", "high", "critical"]


class RiskConfig(BaseModel):
    """Tunable in one place. Defaults follow the design doc; calibrate them by replaying decisions."""

    new_resource: int = 15
    volume_cap: int = 25
    volume_no_baseline: int = 10
    volume_min_rows: int = 100  # smaller requests never raise a volume signal
    volume_min_samples: int = 20  # below this the baseline is not trusted (cold start)
    cold_start_rows: int = 1000
    unbounded_read: int = 15
    sensitive_then_external: int = 30
    tainted_session: int = 15
    low_assurance_production: int = 20
    new_session: int = 5
    new_session_seconds: int = 300
    repeated_denials_cap: int = 20
    destructive_verb: int = 10
    unknown_tool: int = 15
    multiple_statements: int = 10
    confidence_penalty: int = 20
    # From the agent inventory (control plane discovery), published in the catalog:
    agent_finding: int = 20  # the agent has an open finding (e.g. it also reaches models directly)
    tool_definition_changed: int = 25  # the tool's definition changed after it was approved

    elevated_row_limit: int = 1000  # elevated-risk SQL reads are capped to this many rows (obligation)
    penalty_after_denials: int = 3
    denial_penalty_points: int = 10
    denial_penalty_half_life_days: float = 7.0
    quarantine_after_denials: int = 5
    quarantine_seconds: int = 900
    # Denials across all of an agent's sessions within 15 minutes before the whole agent is
    # quarantined (so a new session_id, or none, doesn't reset the count).
    agent_quarantine_after_denials: int = 10
    internal_domains: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class Signal:
    code: str
    points: int
    detail: str = ""


@dataclass(frozen=True)
class Assessment:
    score: int
    band: Band
    trust: int
    confidence: float
    inherent: int
    signals: tuple[Signal, ...] = field(default_factory=tuple)

    @property
    def codes(self) -> list[str]:
        return [s.code for s in self.signals]


def current_trust(base: int, view: SessionView, now: float) -> int:
    lost = sum(p.remaining(now) for p in view.penalties)
    return max(0, min(base, round(base - lost)))


def band_for(score: int, trust: int) -> Band:
    if score >= 80:
        return "critical"
    if score < 30 + 0.2 * trust:
        return "low"
    if score < min(80, 55 + 0.2 * trust):
        return "elevated"
    return "high"


SENSITIVE_LABELS = ("holds:PII", "holds:CONFIDENTIAL")


def assess(
    *,
    inherent: int,
    base_trust: int,
    descriptor: ActionDescriptor,
    view: SessionView,
    stage: str,
    environment: str,
    assurance: str,
    data_classification: str,
    has_session_id: bool,
    cfg: RiskConfig,
    now: float,
    agent_findings: tuple[str, ...] = (),
    tool_flagged: bool = False,
) -> Assessment:
    sig: list[Signal] = []
    d = descriptor
    tool_like = d.kind not in ("model",)

    if tool_like and d.target and view.first_seen_target and stage in ("tool",):
        sig.append(Signal("NEW_RESOURCE", cfg.new_resource, f"first access to {d.target} in 90 days"))

    rows = d.rows_requested
    if tool_like and rows is not None and rows >= cfg.volume_min_rows:
        if view.volume_p95 is not None and view.volume_samples >= cfg.volume_min_samples:
            ratio = rows / max(view.volume_p95, 1.0)
            if ratio >= 2:
                pts = min(cfg.volume_cap, round(8 * math.log2(ratio)))
                sig.append(Signal(f"VOLUME_{int(ratio)}X", pts, f"{rows} rows vs p95 {view.volume_p95:.0f}"))
        elif rows >= cfg.cold_start_rows:
            sig.append(Signal("VOLUME_NO_BASELINE", cfg.volume_no_baseline, f"{rows} rows, no baseline yet"))

    if d.kind == "sql" and d.verb == "read" and rows is None and d.has_filter is False:
        sig.append(Signal("UNBOUNDED_READ", cfg.unbounded_read, "no LIMIT and no WHERE"))

    holds_sensitive = any(lbl in view.labels for lbl in SENSITIVE_LABELS) or data_classification in (
        "PII",
        "CONFIDENTIAL",
    )
    if d.destination == "external" and d.verb in ("send", "write") and holds_sensitive:
        sig.append(
            Signal("SENSITIVE_THEN_EXTERNAL", cfg.sensitive_then_external, f"sensitive data to {d.destination_host}")
        )

    if stage == "tool" and "untrusted_input" in view.labels:
        sig.append(Signal("TAINTED_SESSION", cfg.tainted_session, "session read untrusted content"))

    if assurance == "A0" and environment == "production":
        sig.append(Signal("LOW_ASSURANCE", cfg.low_assurance_production, "agent_id is only claimed (A0)"))

    if not has_session_id:
        sig.append(Signal("NO_SESSION", cfg.new_session, "no session_id"))
    elif not view.has_session or view.age_seconds < cfg.new_session_seconds:
        sig.append(Signal("NEW_SESSION", cfg.new_session, "session started recently"))

    denials = max(view.denials, view.agent_recent_denials)
    if denials >= 1:
        sig.append(
            Signal("REPEATED_DENIALS", min(cfg.repeated_denials_cap, 10 * denials), f"{denials} recent denial(s)")
        )

    if stage == "tool" and d.verb in ("delete", "admin"):
        sig.append(Signal("DESTRUCTIVE_VERB", cfg.destructive_verb, d.verb))
    if stage == "tool" and not d.parsed:
        sig.append(Signal("UNKNOWN_TOOL", cfg.unknown_tool, "; ".join(d.notes) or "unrecognised tool"))
    if d.statements > 1:
        sig.append(Signal("MULTIPLE_STATEMENTS", cfg.multiple_statements, f"{d.statements} statements"))
    if agent_findings:
        sig.append(Signal("AGENT_FINDING", cfg.agent_finding, ", ".join(sorted(set(agent_findings)))))
    if stage == "tool" and tool_flagged:
        sig.append(Signal("TOOL_DEFINITION_CHANGED", cfg.tool_definition_changed, "changed since it was approved"))

    # Confidence: how much of the context we actually had. Missing context counts as risk.
    parts = [
        (0.3, view.available),
        (0.2, has_session_id),
        (0.3, d.parsed or stage != "tool"),
        (0.2, rows is None or (view.volume_p95 is not None and view.volume_samples >= cfg.volume_min_samples)),
    ]
    confidence = round(sum(w for w, ok in parts if ok), 2)
    penalty = round(cfg.confidence_penalty * (1 - confidence))
    if penalty:
        sig.append(Signal("LOW_CONFIDENCE", penalty, f"confidence {confidence:.2f}"))

    score = max(0, min(100, inherent + sum(s.points for s in sig)))
    trust = current_trust(base_trust, view, now)
    return Assessment(score, band_for(score, trust), trust, confidence, inherent, tuple(sig))
