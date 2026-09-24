"""Human review queue for ESCALATE decisions.

The gateway holds the request and files a review here with the (encrypted) payload and a short
preview. A reviewer approves or rejects it; the agent polls the gateway, which asks here. An
unanswered review expires after `review_ttl_minutes` and then counts as rejected (fail-closed).
Viewing the raw payload needs the `reviewer-raw` role and is recorded.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from ..domain.rbac import Permission, Principal
from ..domain.records import ReviewRecord, utcnow
from ..errors import NotFound, StateConflict
from ..metrics import REVIEW_DECISIONS
from .context import Ctx

PREVIEW_CHARS = 500


class ReviewService:
    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx
        self.store = ctx.store

    async def create(
        self,
        *,
        tenant_id: str,
        environment: str,
        request_id: str,
        stage: str,
        agent_id: str,
        guardrail_id: str,
        reason: str,
        risk_score: int,
        payload: dict[str, Any],
        preview: str,
        ttl_minutes: int | None = None,
    ) -> ReviewRecord:
        review = ReviewRecord(
            tenant_id=tenant_id,
            environment=environment,  # type: ignore[arg-type]
            request_id=request_id,
            stage=stage,
            agent_id=agent_id,
            guardrail_id=guardrail_id,
            reason=reason[:1000],
            risk_score=risk_score,
            preview=preview[:PREVIEW_CHARS],
            payload_enc=self.ctx.cipher.encrypt(payload),
            expires_at=utcnow() + timedelta(minutes=ttl_minutes or self.ctx.policy.review_ttl_minutes),
        )
        await self.store.add_review(review)
        await self.ctx.log("review", review.id, "create", f"gateway ({environment})", after={"tenant_id": tenant_id})
        return review

    async def _get(self, review_id: str) -> ReviewRecord:
        r = await self.store.get_review(review_id)
        if r is None:
            raise NotFound(f"review {review_id} not found")
        return r

    async def list(self, p: Principal, tenant_id: str | None, status: str | None) -> list[tuple[ReviewRecord, str]]:
        """Returns (review, effective_status). `status=expired` filters on the effective status."""
        if tenant_id is None and not p.is_platform:
            tenant_id = p.tenant_id
        p.require(Permission.READ, tenant_id if tenant_id is not None else p.tenant_id)
        stored_status = "pending" if status == "expired" else status
        rows = await self.store.list_reviews(tenant_id, stored_status)
        out = [(r, r.effective_status()) for r in rows]
        return [(r, s) for r, s in out if status is None or s == status]

    async def get(self, p: Principal, review_id: str, *, include_raw: bool = False) -> tuple[ReviewRecord, dict | None]:
        r = await self._get(review_id)
        p.require(Permission.READ, r.tenant_id)
        raw = None
        if include_raw:
            p.require(Permission.REVIEWS_RAW, r.tenant_id)
        await self.ctx.log("review", review_id, "view", p.actor)  # every view is audited (plan section 7)
        if include_raw:
            raw = self.ctx.cipher.decrypt(r.payload_enc)
            await self.store.add_review_raw_viewer(review_id, p.actor)
            r = r.model_copy(update={"raw_viewed_by": [*r.raw_viewed_by, p.actor]})
            await self.ctx.log("review", review_id, "view_raw", p.actor)
        return r, raw

    async def decide(self, p: Principal, review_id: str, approve: bool, note: str = "") -> ReviewRecord:
        r = await self._get(review_id)
        p.require(Permission.REVIEWS_DECIDE, r.tenant_id)
        state = r.effective_status()
        if state != "pending":
            raise StateConflict(f"review is {state}")
        updated = r.model_copy(
            update={
                "status": "approved" if approve else "rejected",
                "reviewer": p.actor,
                "decided_at": utcnow(),
                "decision_note": note[:1000],
            }
        )
        won = await self.store.decide_review(
            review_id,
            status=updated.status,
            reviewer=p.actor,
            decided_at=updated.decided_at,  # type: ignore[arg-type]
            decision_note=updated.decision_note,
        )
        if not won:  # someone else decided it between our read and this write
            current = await self._get(review_id)
            raise StateConflict(f"review is already {current.effective_status()} (by {current.reviewer})")
        await self.ctx.log("review", review_id, "approve" if approve else "reject", p.actor, after={"note": note[:200]})
        REVIEW_DECISIONS.labels("approved" if approve else "rejected").inc()
        return updated

    async def status_for_gateway(self, review_id: str, tenant_id: str) -> dict[str, Any]:
        """What the gateway returns to the agent. The payload is only released once approved."""
        r = await self._get(review_id)
        if r.tenant_id != tenant_id:
            raise NotFound(f"review {review_id} not found")
        state = r.effective_status()
        decision = {"pending": "escalate", "approved": "allow"}.get(state, "block")
        reason = {
            "pending": "waiting for human review",
            "approved": f"approved by {r.reviewer}",
            "rejected": f"rejected by {r.reviewer}",
            "expired": "review expired without a decision (fail-closed)",
        }[state]
        if r.decision_note and state in ("approved", "rejected"):
            reason += f": {r.decision_note}"
        return {
            "escalation_id": r.id,
            "status": state,
            "decision": decision,
            "reason": reason,
            "reviewer": r.reviewer,
            "payload": self.ctx.cipher.decrypt(r.payload_enc) if state == "approved" else None,
        }
