"""The decision table: the only place a final verdict is made.

Inputs are already-computed facts (policy result, guardrail outcome, risk band, descriptor,
session state). The table is deliberately small and explicit so it can be reviewed line by line,
tested exhaustively and replayed against recorded traffic. Nothing here calls a model.

Outcomes, strongest first:

    deny > quarantine_session > hold > verify > throttle > modify > allow_restricted > allow

`verify` means "more evidence needed". With the verification engine (app/verify) the gateway
resolves it to allow, a pending user confirmation or a hold; without one (VERIFICATION_ENABLED=false)
it falls back to `hold` (human review), the strictest non-final answer.

An enforcing advisor (app/advise) can turn an allowing outcome into `verify` (ADVISOR_VERIFY); it
can never turn anything into a more permissive outcome.

`allow_restricted` carries obligations (e.g. {"row_limit": 1000}). A caller that hasn't declared
`accepts_obligations` would silently ignore them, so for such callers the answer becomes `hold`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from app.context.descriptors import ActionDescriptor
from app.risk.engine import Band, RiskConfig
from guardrail_sdk import Decision

Outcome = Literal["allow", "allow_restricted", "modify", "throttle", "verify", "hold", "quarantine_session", "deny"]
ORDER: tuple[Outcome, ...] = (
    "allow", "allow_restricted", "modify", "throttle", "verify", "hold", "quarantine_session", "deny",
)  # fmt: skip


def strongest(*outcomes: Outcome) -> Outcome:
    return max(outcomes, key=ORDER.index)


@dataclass(frozen=True)
class TableResult:
    outcome: Outcome
    reason_codes: tuple[str, ...]
    obligations: dict[str, Any] = field(default_factory=dict)

    @property
    def legacy(self) -> Decision:
        return to_legacy(self.outcome)


def to_legacy(outcome: str, modified: bool = False) -> Decision:
    if outcome in ("deny", "quarantine_session"):
        return Decision.BLOCK
    if outcome in ("hold", "verify"):
        return Decision.ESCALATE
    if outcome == "throttle":
        return Decision.BLOCK
    if outcome == "modify" or modified:
        return Decision.MODIFY
    return Decision.ALLOW


def from_engine(decision: Decision) -> Outcome:
    return {
        Decision.BLOCK: "deny",
        Decision.ESCALATE: "hold",
        Decision.MODIFY: "modify",
        Decision.ALLOW: "allow",
    }[decision]  # type: ignore[return-value]


def risk_outcome(band: Band, d: ActionDescriptor, cfg: RiskConfig) -> tuple[Outcome, dict[str, Any], list[str]]:
    """What the risk band alone asks for (before policy and guardrails are combined in)."""
    if band == "critical":
        return "hold", {}, ["RISK_CRITICAL"]
    if band == "high":
        return "verify", {}, ["RISK_HIGH"]
    if band == "elevated":
        big = d.rows_requested is None or d.rows_requested > cfg.elevated_row_limit
        if d.kind == "sql" and d.verb == "read" and big:
            return "allow_restricted", {"row_limit": cfg.elevated_row_limit}, ["RISK_ELEVATED", "ROW_LIMIT"]
        if d.writes and d.destination == "external":
            return "verify", {}, ["RISK_ELEVATED", "EXTERNAL_WRITE"]
        return "allow", {}, ["RISK_ELEVATED"]
    return "allow", {}, []


def decide(
    *,
    policy_allow: bool,
    engine_decision: Decision,
    band: Band,
    descriptor: ActionDescriptor,
    quarantined: bool,
    accepts_obligations: bool,
    cfg: RiskConfig,
    verification_available: bool = False,
    advisor_verify: bool = False,
) -> TableResult:
    if not policy_allow:
        return TableResult("deny", ("POLICY_DENY",))
    if quarantined:
        return TableResult("quarantine_session", ("SESSION_QUARANTINED",))

    r_out, obligations, codes = risk_outcome(band, descriptor, cfg)
    out = strongest(r_out, from_engine(engine_decision))
    if engine_decision == Decision.BLOCK:
        codes.append("GUARDRAIL_BLOCK")
    elif engine_decision == Decision.ESCALATE:
        codes.append("GUARDRAIL_ESCALATE")

    if advisor_verify and out in ("allow", "allow_restricted", "modify"):
        # An enforcing advisor asked for evidence. It can only make the outcome stricter.
        out = "verify"
        codes.append("ADVISOR_VERIFY")
    if out == "verify" and not verification_available:
        out = "hold"
        codes.append("VERIFY_AS_HOLD")
    if obligations and out in ("allow", "allow_restricted", "modify") and not accepts_obligations:
        out = "hold"
        codes.append("OBLIGATIONS_UNSUPPORTED")
    if out not in ("allow", "allow_restricted", "modify"):
        obligations = {}
    return TableResult(out, tuple(dict.fromkeys(codes)), obligations)
