"""Verification engine: turn a `verify` outcome into allow, a pending user confirmation, or a hold.

Called by ContextualDecisions only when the decision table said `verify`:

    1. what does this action need (required) and what do we already have (current + evidence)?
    2. gap closed (e.g. the user already confirmed this exact request) -> allow, evidence consumed
    3. otherwise plan the cheapest verifiers that close the gap:
         dry run            run now (EXPLAIN on a read replica); passes -> allow
         user confirmation  open a Verification; the request answers `verify` (HTTP 202) and the
                            agent retries the identical request after the user confirmed
         human only         hold for the review queue (the existing path)

Shadow mode calls `describe()` instead: the plan is reported, nothing runs, nothing is stored.
A failure anywhere here is a hold, never an allow (fail closed).
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from app.context.descriptors import ActionDescriptor
from app.verify.dryrun import SqlDryRun
from app.verify.model import (
    EVIDENCE_TTL_SECONDS,
    VERIFICATION_TTL_SECONDS,
    Evidence,
    Verification,
    current,
    gap,
    required,
    summary_for,
)
from app.verify.planner import DRY_RUN, USER_CONFIRMATION, Plan, VerifierSpec, plan
from app.verify.store import VerificationStore
from app.verify.user_token import TokenRejected, UserTokenVerifier

USER_CONFIRMATION_CHANNEL = "user_confirmation"


class VerificationNotFound(LookupError):
    pass


class VerificationClosed(Exception):
    """Already confirmed, rejected or expired."""


@dataclass(frozen=True)
class VerifyContext:
    """Everything about the request the engine needs (no payload values)."""

    tenant_id: str
    agent_id: str
    user_id: str | None
    request_hash: str
    descriptor: ActionDescriptor
    codes: tuple[str, ...]
    environment: str
    assurance: str
    channels: tuple[str, ...]
    tool_name: str | None
    resource: str | None
    sql: str | None


@dataclass(frozen=True)
class Resolution:
    outcome: str  # allow | verify | hold | deny
    codes: tuple[str, ...]
    verification: Verification | None = None
    plan: tuple[str, ...] = ()


class VerificationEngine:
    def __init__(
        self,
        store: VerificationStore,
        *,
        dry_run: SqlDryRun | None = None,
        user_tokens: UserTokenVerifier | None = None,
        max_dry_run_rows: int = 10_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.dry_run = dry_run
        self.user_tokens = user_tokens
        self.max_rows = max_dry_run_rows
        self._now = clock

    @property
    def user_confirmation_enabled(self) -> bool:
        return self.user_tokens is not None and self.user_tokens.enabled

    def available(self, c: VerifyContext) -> list[VerifierSpec]:
        out: list[VerifierSpec] = []
        if self.dry_run is not None and c.sql and self.dry_run.applicable(c.descriptor, c.tool_name, c.resource):
            out.append(DRY_RUN)
        if USER_CONFIRMATION_CHANNEL in c.channels and c.user_id and self.user_confirmation_enabled:
            out.append(USER_CONFIRMATION)
        return out

    def _plan(self, c: VerifyContext, evidence: Iterable[Evidence]) -> tuple[dict[str, int], Plan | None]:
        need = required(c.descriptor, c.codes, c.environment)
        have = current(assurance=c.assurance, d=c.descriptor, codes=c.codes, evidence=evidence)
        g = gap(need, have)
        return g, plan(g, self.available(c))

    # ---- shadow ---------------------------------------------------------------------------------

    def describe(self, c: VerifyContext) -> Resolution:
        """What enforce mode would do, without running or storing anything (evidence not consulted)."""
        _, p = self._plan(c, ())
        if p is None:
            return Resolution("allow", ("VERIFIED",))
        if p.needs_human_review:
            return Resolution("hold", ("VERIFY_NEEDS_HUMAN",), plan=tuple(p.kinds))
        return Resolution("verify", tuple(f"VERIFY_PLAN_{k.upper()}" for k in p.kinds), plan=tuple(p.kinds))

    # ---- enforce --------------------------------------------------------------------------------

    async def resolve(self, c: VerifyContext) -> Resolution:
        try:
            return await self._resolve(c)
        except Exception:  # noqa: BLE001 - fail closed: the review queue still gets the request
            return Resolution("hold", ("VERIFY_ERROR",))

    async def _resolve(self, c: VerifyContext) -> Resolution:
        evidence = await self.store.evidence(c.tenant_id, c.request_hash)
        if any(e.kind == "user_confirmation" and not e.passed for e in evidence):
            await self.store.consume_evidence(c.tenant_id, c.request_hash)
            return Resolution("deny", ("USER_REJECTED",))
        g, p = self._plan(c, evidence)
        if p is None:
            # Read-and-delete in one step, then decide on what we actually got: of two identical
            # retries racing on one confirmation, only one is allowed; the other plans afresh.
            evidence = await self.store.take_evidence(c.tenant_id, c.request_hash)
            g, p = self._plan(c, evidence)
            if p is None:
                kinds = dict.fromkeys(f"EVIDENCE_{e.kind.upper()}" for e in evidence if e.passed)
                return Resolution("allow", ("VERIFIED", *kinds))
        if p.needs_human_review:
            return Resolution("hold", ("VERIFY_NEEDS_HUMAN",), plan=tuple(p.kinds))

        codes: list[str] = []
        for step in p.inline:
            if step.kind == DRY_RUN.kind and self.dry_run is not None and c.sql is not None:
                res = await self.dry_run.run(c.sql, c.tool_name, c.resource)
                if not res.ok:
                    return Resolution("hold", ("DRY_RUN_FAILED",), plan=tuple(p.kinds))
                if res.estimated_rows is None or res.estimated_rows > self.max_rows:
                    return Resolution("hold", ("DRY_RUN_TOO_MANY_ROWS",), plan=tuple(p.kinds))
                now = self._now()
                ev = Evidence(
                    kind="dry_run",
                    request_hash=c.request_hash,
                    passed=True,
                    strength=dict(DRY_RUN.closes),
                    detail={"estimated_rows": res.estimated_rows},
                    issued_at=now,
                    expires_at=now + EVIDENCE_TTL_SECONDS,
                )
                evidence = [*evidence, ev]
                codes.append("EVIDENCE_DRY_RUN")
                if p.pending:  # keep it for the retry after the person confirmed
                    await self.store.add_evidence(c.tenant_id, ev)

        if p.pending:
            v = await self.store.pending_for(c.tenant_id, c.request_hash)
            if v is None:
                now = self._now()
                v = Verification(
                    id=uuid.uuid4().hex,
                    tenant_id=c.tenant_id,
                    request_hash=c.request_hash,
                    kind=USER_CONFIRMATION.kind,
                    agent_id=c.agent_id,
                    user_id=c.user_id,
                    summary=summary_for(c.agent_id, c.descriptor),
                    status="pending",
                    created_at=now,
                    expires_at=now + VERIFICATION_TTL_SECONDS,
                )
                await self.store.put_verification(v)
            return Resolution("verify", (*codes, "VERIFY_USER_CONFIRMATION"), verification=v, plan=tuple(p.kinds))

        g = gap(
            required(c.descriptor, c.codes, c.environment),
            current(assurance=c.assurance, d=c.descriptor, codes=c.codes, evidence=evidence),
        )
        if g:  # the plan said it would close; if it didn't, a person decides
            return Resolution("hold", ("VERIFY_INCOMPLETE",), plan=tuple(p.kinds))
        await self.store.take_evidence(c.tenant_id, c.request_hash)  # anything stored for it is spent
        return Resolution("allow", ("VERIFIED", *codes), plan=tuple(p.kinds))

    # ---- the person's answer (POST /v1/verifications/{id}/confirm) -------------------------------

    async def confirm(
        self, tenant_id: str, vid: str, *, user_token: str, approve: bool, caller_agent_id: str | None = None
    ) -> Verification:
        """Raises VerificationNotFound, VerificationClosed or TokenRejected. Returns the updated record.

        `caller_agent_id` is the agent the confirming API key is bound to (None for unbound keys)."""
        v = await self.store.get_verification(tenant_id, vid)
        if v is None:
            raise VerificationNotFound(f"verification {vid} not found")
        if v.status != "pending":
            raise VerificationClosed(f"verification is already {v.status}")
        if self.user_tokens is None:
            raise TokenRejected("user confirmation is not configured on this gateway")
        nonce_bound = self.user_tokens.cfg.require_nonce
        if not nonce_bound and caller_agent_id is not None and caller_agent_id == v.agent_id:
            raise TokenRejected("the agent's own key can't confirm its request; use the host app's key")
        claims = await self.user_tokens.verify(user_token, v.user_id or "", expected_nonce=v.id)
        now = self._now()
        await self.store.add_evidence(
            tenant_id,
            Evidence(
                kind="user_confirmation",
                request_hash=v.request_hash,
                passed=approve,
                strength=dict(USER_CONFIRMATION.closes) if approve else {},
                detail={"sub": str(claims.get("sub", "")), "acr": claims.get("acr")},
                issued_at=now,
                expires_at=now + EVIDENCE_TTL_SECONDS,
            ),
        )
        done = Verification(**{**v.__dict__, "status": "confirmed" if approve else "rejected"})
        await self.store.put_verification(done)
        return done
