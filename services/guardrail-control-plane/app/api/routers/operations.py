"""Review queue, gateway fleet, change log, admin keys, analytics, simulate."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field

from guardrail_sdk.api import GuardRequest
from guardrail_sdk.models import Stage

from ...domain.rbac import PLATFORM_ONLY, Permission, Principal
from ...domain.records import ENVIRONMENTS, Environment
from ..container import Container
from ..deps import container, principal

router = APIRouter(tags=["operations"])


class DecisionIn(BaseModel):
    note: str = Field("", max_length=1000)


class AdminKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    roles: list[str]
    tenant_id: str | None = None


class SimulateIn(BaseModel):
    environment: Environment
    source: Literal["working", "current"] = "working"
    tenant_id: str
    stage: Stage
    request: GuardRequest


def _review_out(r: Any, status: str) -> dict[str, Any]:
    return {**r.model_dump(mode="json", exclude={"payload_enc"}), "status": status}


# ---- who am I (the console uses this to show only what the key can do) ------------------------


@router.get("/me")
async def me(p: Principal = Depends(principal), c: Container = Depends(container)):
    policy = c.ctx.policy
    return {
        "key_id": p.key_id,
        "name": p.name,
        "roles": sorted(p.roles),
        "tenant_id": p.tenant_id,
        "platform": p.is_platform,
        "permissions": sorted(perm.value for perm in p.permissions() if p.is_platform or perm not in PLATFORM_ONLY),
        "environments": list(ENVIRONMENTS),
        "two_person_environments": sorted(policy.two_person_environments),
        "review_ttl_minutes": policy.review_ttl_minutes,
        "features": {
            "simulate": bool(c.gateway_url or c.gateway_urls),
            "analytics": c.analytics_fetch is not None,
        },
    }


# ---- review queue -----------------------------------------------------------------------------


@router.get("/reviews")
async def list_reviews(
    tenant_id: str | None = None,
    status: str | None = Query(None, pattern="^(pending|approved|rejected|expired)$"),
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    return [_review_out(r, s) for r, s in await c.reviews.list(p, tenant_id, status)]


@router.get("/reviews/{review_id}")
async def get_review(
    review_id: str, include_raw: bool = False, p: Principal = Depends(principal), c: Container = Depends(container)
):
    r, raw = await c.reviews.get(p, review_id, include_raw=include_raw)
    out = _review_out(r, r.effective_status())
    if include_raw:
        out["payload"] = raw
    return out


@router.post("/reviews/{review_id}/approve")
async def approve_review(
    review_id: str, body: DecisionIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    r = await c.reviews.decide(p, review_id, approve=True, note=body.note)
    return _review_out(r, r.effective_status())


@router.post("/reviews/{review_id}/reject")
async def reject_review(
    review_id: str, body: DecisionIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    r = await c.reviews.decide(p, review_id, approve=False, note=body.note)
    return _review_out(r, r.effective_status())


# ---- fleet / history / keys -------------------------------------------------------------------


@router.get("/environments/{environment}/gateways")
async def gateways(environment: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    return [{**g.model_dump(mode="json"), "live": live} for g, live in await c.gateways.list(p, environment)]


@router.get("/changes")
async def changes(
    entity: str | None = None,
    entity_id: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    p.require(Permission.READ)  # platform-wide history: platform keys only
    return [ch.model_dump(mode="json") for ch in await c.ctx.store.list_changes(entity, entity_id, limit)]


@router.post("/admin-keys", status_code=201)
async def create_admin_key(body: AdminKeyIn, p: Principal = Depends(principal), c: Container = Depends(container)):
    key, raw = await c.admin_keys.create(p, body.name, body.roles, body.tenant_id)
    return {**key.model_dump(mode="json", exclude={"key_hash"}), "key": raw}


@router.get("/admin-keys")
async def list_admin_keys(p: Principal = Depends(principal), c: Container = Depends(container)):
    return [k.model_dump(mode="json", exclude={"key_hash"}) for k in await c.admin_keys.list(p)]


@router.delete("/admin-keys/{key_id}", status_code=204)
async def revoke_admin_key(key_id: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    await c.admin_keys.revoke(p, key_id)
    return Response(status_code=204)


# ---- simulate -------------------------------------------------------------------------------------


@router.post("/simulate")
async def simulate(body: SimulateIn, p: Principal = Depends(principal), c: Container = Depends(container)):
    """Run a request through a draft (working set) or the live snapshot on a real gateway, without
    enforcing or auditing it. Shows each guardrail's decision before you publish."""
    return await c.simulation.run(
        p,
        environment=body.environment,
        source=body.source,
        tenant_id=body.tenant_id,
        stage=body.stage,
        request=body.request,
    )


# ---- analytics (reads the gateway's audit schema through a read-only DSN) ---------------------------


@router.get("/analytics/guardrails")
async def analytics(
    environment: Environment | None = None,
    tenant_id: str | None = None,
    hours: int = Query(24, ge=1, le=24 * 90),
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    """Decisions per stage and per guardrail, latency and a time series, from the audit log."""
    return await c.analytics.guardrails(p, environment=environment, tenant_id=tenant_id, hours=hours)
