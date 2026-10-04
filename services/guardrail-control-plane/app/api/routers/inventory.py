"""Agent discovery and inventory API (prefix /inv/v1, X-Admin-Key like /cp/v1).

Connectors (platform admins):
    GET    /inv/v1/connector-kinds
    GET    /inv/v1/tenants/{t}/connectors               POST (create)
    GET    /inv/v1/tenants/{t}/connectors/{id}          PATCH, DELETE
    POST   /inv/v1/tenants/{t}/connectors/{id}/sync     run now (tenant editors too)
    GET    /inv/v1/tenants/{t}/connectors/{id}/runs

Inventory (tenant keys see their own tenant):
    GET    /inv/v1/tenants/{t}/entities?kind=&state=&agents_only=&q=
    GET    /inv/v1/tenants/{t}/entities/{id}            entity + evidence + relations + findings
    GET    /inv/v1/tenants/{t}/entities/{id}/graph?depth=2&as_of=<ISO time>
    POST   /inv/v1/tenants/{t}/entities/{id}/link       {"agent_id"}
    POST   /inv/v1/tenants/{t}/entities/{id}/register   {"agent_id", "base_trust_score", "allowed_tools", "owner"}
    POST   /inv/v1/tenants/{t}/entities/{id}/ignore     {"reason", "days"} (days 0 = stop ignoring)
    GET    /inv/v1/tenants/{t}/coverage?environment=
    GET    /inv/v1/tenants/{t}/summary
    GET    /inv/v1/tenants/{t}/findings?status=open&kind=
    PATCH  /inv/v1/tenants/{t}/findings/{id}            {"status": "accepted"|"resolved"|"open", "note"}
    POST   /inv/v1/tenants/{t}/reconcile
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field

from ...domain.rbac import Principal
from ..container import Container
from ..deps import container, principal

router = APIRouter(tags=["inventory"])
T = "/tenants/{tenant_id}"


class ConnectorIn(BaseModel):
    kind: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=100)
    config: dict[str, Any] = Field(default_factory=dict)
    environment: Literal["dev", "staging", "production"] | None = None
    interval_minutes: int = Field(default=60, ge=5, le=10080)
    enabled: bool = True


class ConnectorPatch(BaseModel):
    """Only the fields present change (null environment = not tied to one)."""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    config: dict[str, Any] | None = None
    environment: Literal["dev", "staging", "production"] | None = None
    interval_minutes: int | None = Field(default=None, ge=5, le=10080)
    enabled: bool | None = None


class LinkIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)


class RegisterIn(LinkIn):
    base_trust_score: int = Field(default=50, ge=0, le=100)
    allowed_tools: list[str] = Field(default_factory=list)
    owner: str | None = Field(default=None, max_length=255)


class IgnoreIn(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    days: int = Field(default=30, ge=0, le=365)


class FindingPatch(BaseModel):
    status: Literal["accepted", "resolved", "open"]
    note: str = Field(default="", max_length=2000)


def _connector(c: Any) -> dict[str, Any]:
    return c.model_dump(mode="json", exclude={"lease_owner"})


def _dump(x: Any) -> Any:
    return x.model_dump(mode="json") if hasattr(x, "model_dump") else x


@router.get("/connector-kinds")
async def connector_kinds(p: Principal = Depends(principal), c: Container = Depends(container)):
    return c.discovery.kinds()


@router.get(T + "/connectors")
async def list_connectors(tenant_id: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    return [_connector(x) for x in await c.discovery.list_connectors(p, tenant_id)]


@router.post(T + "/connectors", status_code=201)
async def create_connector(
    tenant_id: str, body: ConnectorIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return _connector(await c.discovery.create_connector(p, tenant_id, **body.model_dump()))


@router.get(T + "/connectors/{connector_id}")
async def get_connector(
    tenant_id: str, connector_id: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return _connector(await c.discovery.get_connector(p, tenant_id, connector_id))


@router.patch(T + "/connectors/{connector_id}")
async def patch_connector(
    tenant_id: str,
    connector_id: str,
    body: ConnectorPatch,
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    changes = body.model_dump(include=body.model_fields_set)
    return _connector(await c.discovery.update_connector(p, tenant_id, connector_id, changes))


@router.delete(T + "/connectors/{connector_id}", status_code=204)
async def delete_connector(
    tenant_id: str, connector_id: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    await c.discovery.delete_connector(p, tenant_id, connector_id)
    return Response(status_code=204)


@router.post(T + "/connectors/{connector_id}/sync")
async def sync_connector(
    tenant_id: str, connector_id: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return _dump(await c.discovery.sync(p, tenant_id, connector_id))


@router.get(T + "/connectors/{connector_id}/runs")
async def list_runs(
    tenant_id: str,
    connector_id: str,
    limit: int = Query(20, ge=1, le=100),
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    return [_dump(r) for r in await c.discovery.list_runs(p, tenant_id, connector_id, limit)]


@router.get(T + "/entities")
async def list_entities(
    tenant_id: str,
    kind: str | None = None,
    state: str | None = None,
    agents_only: bool = False,
    q: str | None = Query(None, max_length=200),
    limit: int = Query(500, ge=1, le=2000),
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    items = await c.discovery.list_entities(
        p, tenant_id, kind=kind, state=state, agents_only=agents_only, query=q, limit=limit
    )
    return [_dump(e) for e in items]


@router.get(T + "/entities/{entity_id}")
async def get_entity(
    tenant_id: str, entity_id: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    d = await c.discovery.get_entity(p, tenant_id, entity_id)
    return {
        "entity": _dump(d["entity"]),
        "evidence": [_dump(o) for o in d["evidence"]],
        "relations": [
            {"edge": _dump(r["edge"]), "direction": r["direction"], "other": r["other"]} for r in d["relations"]
        ],
        "findings": [_dump(f) for f in d["findings"]],
    }


@router.get(T + "/entities/{entity_id}/graph")
async def entity_graph(
    tenant_id: str,
    entity_id: str,
    depth: int = Query(2, ge=1, le=4),
    as_of: datetime | None = None,
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    g = await c.discovery.graph(p, tenant_id, entity_id, depth=depth, as_of=as_of)
    return {
        **g,
        "as_of": g["as_of"].isoformat() if g["as_of"] else None,
        "edges": [
            {
                **e,
                "valid_from": e["valid_from"].isoformat(),
                "valid_to": e["valid_to"].isoformat() if e["valid_to"] else None,
            }
            for e in g["edges"]
        ],
    }


@router.post(T + "/entities/{entity_id}/link")
async def link_entity(
    tenant_id: str, entity_id: str, body: LinkIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return _dump(await c.discovery.link(p, tenant_id, entity_id, body.agent_id))


@router.post(T + "/entities/{entity_id}/register", status_code=201)
async def register_entity(
    tenant_id: str,
    entity_id: str,
    body: RegisterIn,
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    e = await c.discovery.register(
        p,
        tenant_id,
        entity_id,
        agent_id=body.agent_id,
        base_trust_score=body.base_trust_score,
        allowed_tools=body.allowed_tools,
        owner=body.owner,
    )
    return _dump(e)


@router.post(T + "/entities/{entity_id}/ignore")
async def ignore_entity(
    tenant_id: str, entity_id: str, body: IgnoreIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return _dump(await c.discovery.ignore(p, tenant_id, entity_id, reason=body.reason, days=body.days))


@router.get(T + "/coverage")
async def coverage(
    tenant_id: str,
    environment: Literal["dev", "staging", "production"] | None = None,
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    out = await c.discovery.coverage(p, tenant_id, environment)
    out["connectors"] = [{**x, "last_run_at": _iso(x["last_run_at"])} for x in out["connectors"]]
    return out


@router.get(T + "/summary")
async def summary(tenant_id: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    return await c.discovery.summary(p, tenant_id)


@router.get(T + "/findings")
async def list_findings(
    tenant_id: str,
    status: Literal["open", "accepted", "resolved", "all"] = "open",
    kind: str | None = None,
    limit: int = Query(500, ge=1, le=2000),
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    items = await c.discovery.list_findings(
        p, tenant_id, status=None if status == "all" else status, kind=kind, limit=limit
    )
    return [_dump(f) for f in items]


@router.patch(T + "/findings/{finding_id}")
async def patch_finding(
    tenant_id: str,
    finding_id: str,
    body: FindingPatch,
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    return _dump(await c.discovery.update_finding(p, tenant_id, finding_id, status=body.status, note=body.note))


@router.post(T + "/reconcile")
async def reconcile(tenant_id: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    return await c.discovery.reconcile(p, tenant_id)


def _iso(v: Any) -> str | None:
    return v.isoformat() if hasattr(v, "isoformat") else v
