"""Contextual decisions: identity binding, action descriptors, session state, risk v2, decision table.

Used by app/gateway/flow.py around the existing Context Builder -> OPA -> Guardrail Engine path:

    identity check   (always enforced: a key bound to agent X can't act as agent Y)
    prepare()        descriptor + session view + risk assessment, before OPA (OPA sees them too)
    decide()         decision table, after OPA and the guardrails
    advise()         advisors (app/advise), uncertain band only, after the guardrails: they can only
                     add capped points or ask for verification
    verify()         when the table said `verify`: dry run / user confirmation / human (app/verify)
    record()         update session state, baselines and trust penalties, after the decision

RISK_MODE controls how much of this changes decisions:
  off      descriptors only (still audited); no session state, no risk v2
  shadow   everything is computed, audited and returned in `risk`, but decisions are unchanged
           (the default: tune the weights by replaying shadow results before enforcing)
  enforce  the decision table's outcome is applied
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from app.advise.contract import build_features
from app.advise.panel import AdvisorPanel, Advisory
from app.audit.digest import payload_digest
from app.context.descriptors import ActionDescriptor, describe, sql_text
from app.gateway.auth import Principal
from app.observability import ADVISOR_POINTS
from app.risk.decision import TableResult, decide
from app.risk.engine import Assessment, RiskConfig, Signal, assess, band_for
from app.session.store import Penalty, SessionStore, SessionUpdate, SessionView
from app.verify.engine import VerificationEngine, VerifyContext
from app.verify.model import Verification, request_hash
from guardrail_sdk import Decision, GuardrailOutcome, GuardRequest, Payload, Stage

RiskMode = Literal["off", "shadow", "enforce"]
SENSITIVE = ("PII", "CONFIDENTIAL")


@dataclass(frozen=True)
class IdentityViolation:
    code: str
    reason: str


@dataclass(frozen=True)
class Prepared:
    descriptor: ActionDescriptor
    view: SessionView | None
    assessment: Assessment | None
    advisory: Advisory | None = None

    def policy_input(self) -> dict[str, Any]:
        out: dict[str, Any] = {"descriptor": self.descriptor.to_dict()}
        if self.view is not None:
            out["session"] = {
                "labels": sorted(self.view.labels),
                "steps": self.view.steps,
                "denials": self.view.denials,
                "first_seen_target": self.view.first_seen_target,
            }
        if self.assessment is not None:
            a = self.assessment
            out["risk_v2"] = {"score": a.score, "band": a.band, "trust": a.trust, "codes": a.codes}
        return out


def _request_digest(body: GuardRequest) -> str:
    """Everything in the request except the payload (hashed separately) and the caller's
    capabilities (`accepts_obligations`, `verification_channels`), which don't change the action."""
    rest = body.model_dump(mode="json", exclude={"payload", "accepts_obligations", "verification_channels"})
    return payload_digest(rest)


# Outcomes that would let a request through; these are checked against open verifications.
FOLLOW_UP_OUTCOMES = frozenset({"allow", "allow_restricted", "modify"})


def volume_key(d: ActionDescriptor) -> str | None:
    return f"{d.kind}:{d.verb}:{d.target}" if d.kind in ("sql", "http", "file") and d.target else None


class ContextualDecisions:
    def __init__(
        self,
        store: SessionStore | None,
        *,
        mode: RiskMode = "shadow",
        require_bound_keys: bool = False,
        config: RiskConfig | None = None,
        clock: Callable[[], float] = time.time,
        verifier: VerificationEngine | None = None,
        advisors: AdvisorPanel | None = None,
    ) -> None:
        self.store = store
        self.verifier = verifier
        self.advisors = advisors
        self.mode: RiskMode = mode if store is not None else "off"
        self.require_bound_keys = require_bound_keys
        self.cfg = config or RiskConfig()
        self._now = clock

    # ---- identity (always on) -------------------------------------------------------------------

    def identity_violation(self, principal: Principal, body: GuardRequest) -> IdentityViolation | None:
        if principal.agent_id is not None and body.agent_id != principal.agent_id:
            return IdentityViolation(
                "KEY_AGENT_MISMATCH", f"this API key is bound to agent {principal.agent_id!r}, not {body.agent_id!r}"
            )
        if principal.agent_id is None and self.require_bound_keys:
            return IdentityViolation(
                "UNBOUND_KEY", "this gateway requires agent-bound API keys (identity assurance A1); this key is A0"
            )
        return None

    # ---- before OPA -----------------------------------------------------------------------------

    async def prepare(
        self, *, principal: Principal, body: GuardRequest, stage: Stage, payload: Payload, environment: str,
        inherent_risk: int, base_trust: int,
    ) -> Prepared:  # fmt: skip
        tool = payload.tool_call
        d = describe(
            stage=stage.value,
            action=body.action,
            resource=body.resource,
            tool_name=tool.name if tool else None,
            tool_arguments=tool.arguments if tool else None,
            request_arguments=body.arguments,
            tool_metadata=body.tool_metadata,
            internal_domains=self.cfg.internal_domains,
        )
        if self.mode == "off" or self.store is None:
            return Prepared(d, None, None)
        view = await self.store.view(
            principal.tenant_id, body.agent_id, body.session_id, target=d.target, volume_key=volume_key(d)
        )
        a = assess(
            inherent=inherent_risk,
            base_trust=base_trust,
            descriptor=d,
            view=view,
            stage=stage.value,
            environment=environment,
            assurance=principal.assurance,
            data_classification=body.data_classification,
            has_session_id=bool(body.session_id),
            cfg=self.cfg,
            now=self._now(),
        )
        return Prepared(d, view, a)

    # ---- after OPA and the guardrails -----------------------------------------------------------

    async def advise(
        self, prepared: Prepared, *, principal: Principal, body: GuardRequest, stage: Stage, payload: Payload,
        results: list[GuardrailOutcome], environment: str, hosted_classes: frozenset[str],
    ) -> Prepared:  # fmt: skip
        """Ask the advisors (uncertain band only). Enforcing advisors can only add points (capped)
        or ask for verification; the band is recomputed from the higher score, so it never drops."""
        a, view = prepared.assessment, prepared.view
        if self.advisors is None or a is None or view is None or not self.advisors.applies(a.band):
            return prepared
        features = build_features(
            stage=stage.value,
            environment=environment,
            data_classification=body.data_classification,
            assurance=principal.assurance,
            payload=payload,
            descriptor=prepared.descriptor,
            view=view,
            assessment=a,
            results=results,
            internal_domains=self.cfg.internal_domains,
        )
        advisory = await self.advisors.advise(
            tenant_id=principal.tenant_id, agent_id=body.agent_id, features=features, hosted_classes=hosted_classes
        )
        if advisory.points > 0:
            ADVISOR_POINTS.labels(stage.value).inc(advisory.points)
            score = min(100, a.score + advisory.points)
            # The agent sees one aggregated code, never which advisor answered or why.
            signals = (*a.signals, Signal("ADVISOR_RISK", advisory.points, ""))
            a = Assessment(score, band_for(score, a.trust), a.trust, a.confidence, a.inherent, signals)
        return Prepared(prepared.descriptor, view, a, advisory)

    def decide(
        self, prepared: Prepared, *, policy_allow: bool, engine_decision: Decision, accepts_obligations: bool
    ) -> TableResult | None:
        if prepared.assessment is None or prepared.view is None:
            return None
        return decide(
            policy_allow=policy_allow,
            engine_decision=engine_decision,
            band=prepared.assessment.band,
            descriptor=prepared.descriptor,
            quarantined=prepared.view.quarantined(self._now()),
            accepts_obligations=accepts_obligations,
            cfg=self.cfg,
            verification_available=self.verifier is not None,
            advisor_verify=bool(prepared.advisory and prepared.advisory.verify),
        )

    async def verify(
        self, prepared: Prepared, table: TableResult, *, principal: Principal, body: GuardRequest, stage: Stage,
        payload: Payload, payload_sha256: str, environment: str,
    ) -> tuple[TableResult, Verification | None]:  # fmt: skip
        """Resolve a `verify` outcome. Shadow mode only describes the plan (nothing runs or is stored).

        In enforce mode an allowing outcome is also checked against verifications already opened
        for this exact request (see VerificationEngine.follow_up)."""
        follow_up = table.outcome in FOLLOW_UP_OUTCOMES and self.enforcing
        if self.verifier is None or (table.outcome != "verify" and not follow_up):
            return table, None
        tool = payload.tool_call
        c = VerifyContext(
            tenant_id=principal.tenant_id,
            agent_id=body.agent_id,
            user_id=body.user_id,
            request_hash=request_hash(
                tenant=principal.tenant_id,
                agent_id=body.agent_id,
                stage=stage.value,
                action=body.action,
                resource=body.resource,
                user_id=body.user_id,
                session_id=body.session_id,
                payload_sha256=payload_sha256,
                request_sha256=_request_digest(body),
            ),  # fmt: skip
            descriptor=prepared.descriptor,
            codes=(*table.reason_codes, *(prepared.assessment.codes if prepared.assessment else ())),
            environment=environment,
            assurance=principal.assurance,
            channels=tuple(body.verification_channels or ()),
            tool_name=tool.name if tool else None,
            resource=body.resource,
            sql=sql_text(tool.arguments if tool else None, body.arguments),
        )
        if follow_up:
            found = await self.verifier.follow_up(c)
            if found is None:
                return table, None
            r = found
        else:
            r = await self.verifier.resolve(c) if self.enforcing else self.verifier.describe(c)
        out = TableResult(r.outcome, tuple(dict.fromkeys((*table.reason_codes, *r.codes))))  # type: ignore[arg-type]
        return out, r.verification

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    # ---- after the decision ---------------------------------------------------------------------

    async def record(
        self,
        prepared: Prepared,
        *,
        principal: Principal,
        body: GuardRequest,
        stage: Stage,
        payload: Payload,
        final: Decision,
    ) -> None:
        if self.store is None or prepared.view is None:
            return
        released = final in (Decision.ALLOW, Decision.MODIFY)
        denied = final == Decision.BLOCK
        d, view = prepared.descriptor, prepared.view
        update = SessionUpdate(denied=denied, allowed=released)
        is_result = payload.tool_call is not None and payload.tool_call.result is not None
        if released:
            if stage == Stage.RETRIEVAL:
                update.labels.add("untrusted_input")
            if is_result and (d.destination == "external" or d.kind in ("http", "unknown")):
                update.labels.add("untrusted_input")
            if (body.tool_metadata or {}).get("trust") == "untrusted":
                update.labels.add("untrusted_input")
            if body.data_classification in SENSITIVE:
                update.labels.add(f"holds:{body.data_classification}")
            if stage == Stage.TOOL and not is_result:
                update.target = d.target
                update.volume_key = volume_key(d)
                update.rows = d.rows_requested
        denials = view.denials + (1 if denied else 0)
        if denied and denials >= self.cfg.penalty_after_denials and not view.penalised:
            update.penalty = Penalty(
                "REPEATED_DENIALS", self.cfg.denial_penalty_points, self.cfg.denial_penalty_half_life_days, self._now()
            )
        if denied and self.enforcing and denials >= self.cfg.quarantine_after_denials:
            update.quarantine_seconds = self.cfg.quarantine_seconds
        if denied and self.enforcing and view.agent_recent_denials + 1 >= self.cfg.agent_quarantine_after_denials:
            update.agent_quarantine_seconds = self.cfg.quarantine_seconds
        await self.store.record(principal.tenant_id, body.agent_id, body.session_id, update)
