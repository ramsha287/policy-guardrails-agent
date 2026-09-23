"""Review queue, gateway fleet, change log, admin keys, analytics, simulate."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field

from guardrail_sdk.api import GuardRequest
from guardrail_sdk.documents import SnapshotDoc
from guardrail_sdk.models import Stage

from ...domain.compiler import compile_snapshot
from ...domain.rbac import Permission, Principal
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
    environment: str
    source: str = Field("working", pattern="^(working|current)$")
    tenant_id: str
    stage: Stage
    request: GuardRequest


def _review_out(r: Any, status: str) -> dict[str, Any]:
    return {**r.model_dump(mode="json", exclude={"payload_enc"}), "status": status}


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
    p.require(Permission.READ, body.tenant_id)
    if not c.gateway_url:
        raise HTTPException(status_code=503, detail="GATEWAY_URL is not configured for simulation")
    if body.source == "current":
        live = await c.ctx.store.current_snapshot(body.environment)
        if live is None:
            raise HTTPException(status_code=404, detail=f"nothing published in {body.environment} yet")
        doc = SnapshotDoc.model_validate(live.document)
    else:
        working = [r.assignment for r in await c.ctx.store.list_assignments(body.environment)]
        result = compile_snapshot(body.environment, working, await c.registry.versions_by_key(), force=True)
        if result.document is None:
            raise HTTPException(status_code=422, detail={"error": "working set is invalid", "errors": result.errors})
        doc = result.document
    catalog = await c.catalog.current_document()
    resp = await c.http.post(
        f"{c.gateway_url.rstrip('/')}/internal/simulate",
        json={
            "snapshot": doc.model_dump(mode="json"),
            "catalog": catalog[0] if catalog else None,
            "tenant_id": body.tenant_id,
            "stage": body.stage.value,
            "request": body.request.model_dump(mode="json"),
        },
        headers={"X-Internal-Token": c.internal_token},
    )
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"gateway simulation failed: HTTP {resp.status_code}")
    return {"source": body.source, "snapshot": doc.version, "result": resp.json()}


# ---- analytics (reads the gateway's audit schema through a read-only DSN) ---------------------------


@router.get("/analytics/guardrails")
async def analytics(
    environment: str,
    tenant_id: str | None = None,
    hours: int = Query(24, ge=1, le=24 * 90),
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    if tenant_id is None and not p.is_platform:
        tenant_id = p.tenant_id
    p.require(Permission.READ, tenant_id if tenant_id is not None else p.tenant_id)
    if c.audit_sessionmaker is None:
        raise HTTPException(status_code=503, detail="AUDIT_DSN is not configured")
    from sqlalchemy import text

    sql = text(
        """
        SELECT r->>'guardrail_id' AS guardrail_id, r->>'version' AS version, e.stage, r->>'decision' AS decision,
               r->>'mode' AS mode, count(*) AS n, avg((r->>'latency_ms')::float) AS avg_latency_ms,
               sum(CASE WHEN r->>'error' IS NOT NULL THEN 1 ELSE 0 END) AS errors
          FROM audit.audit_events e, jsonb_array_elements(e.guardrail_results) r
         WHERE e.environment = :env
           AND e.created_at > now() - make_interval(hours => :hours)
           AND (CAST(:tenant AS text) IS NULL OR e.tenant_id = :tenant)
         GROUP BY 1, 2, 3, 4, 5
         ORDER BY 1, 3, 4
        """
    )
    async with c.audit_sessionmaker() as s:  # type: ignore[operator]
        rows = (await s.execute(sql, {"env": environment, "hours": hours, "tenant": tenant_id})).mappings().all()
    return {"environment": environment, "tenant_id": tenant_id, "hours": hours, "rows": [dict(r) for r in rows]}
