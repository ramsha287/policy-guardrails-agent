"""Tenants, gateway API keys, agents (base trust), actions (base risk), score modifiers."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field

from ...domain.rbac import Permission, Principal
from ...domain.records import Environment
from ..container import Container
from ..deps import container, principal

router = APIRouter(tags=["catalog"])


class TenantIn(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    name: str = Field(min_length=1, max_length=255)


class TenantPatch(BaseModel):
    status: Literal["active", "suspended"]


class ApiKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=lambda: ["guard:invoke"])
    environments: list[Environment] | None = None
    expires_at: datetime | None = None


class AgentIn(BaseModel):
    base_trust_score: int = Field(ge=0, le=100)
    allowed_tools: list[str] = Field(default_factory=lambda: ["*"])
    owner: str | None = None


class ActionIn(BaseModel):
    action: str = Field(min_length=1, max_length=128)
    resource_pattern: str = Field("*", max_length=256)
    base_risk_score: int = Field(ge=0, le=100)


class ModifierIn(BaseModel):
    kind: Literal["classification", "environment"]
    value: str = Field(min_length=1, max_length=64)
    delta: int = Field(ge=-100, le=100)


def _key_out(k: Any) -> dict[str, Any]:
    return k.model_dump(mode="json", exclude={"key_hash"})


@router.post("/tenants", status_code=201)
async def create_tenant(body: TenantIn, p: Principal = Depends(principal), c: Container = Depends(container)):
    return (await c.catalog.create_tenant(p, body.id, body.name)).model_dump(mode="json")


@router.get("/tenants")
async def list_tenants(p: Principal = Depends(principal), c: Container = Depends(container)):
    return [t.model_dump(mode="json") for t in await c.catalog.list_tenants(p)]


@router.patch("/tenants/{tenant_id}")
async def patch_tenant(
    tenant_id: str, body: TenantPatch, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return (await c.catalog.set_tenant_status(p, tenant_id, body.status)).model_dump(mode="json")


@router.post("/tenants/{tenant_id}/api-keys", status_code=201)
async def create_api_key(
    tenant_id: str, body: ApiKeyIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    key, raw = await c.catalog.create_api_key(p, tenant_id, body.name, body.scopes, body.environments, body.expires_at)
    return {**_key_out(key), "key": raw, "note": "Store this key now; only its hash is kept."}


@router.get("/tenants/{tenant_id}/api-keys")
async def list_api_keys(tenant_id: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    return [_key_out(k) for k in await c.catalog.list_api_keys(p, tenant_id)]


@router.delete("/tenants/{tenant_id}/api-keys/{key_id}")
async def revoke_api_key(
    tenant_id: str, key_id: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return _key_out(await c.catalog.revoke_api_key(p, tenant_id, key_id))


@router.put("/tenants/{tenant_id}/agents/{agent_id}")
async def put_agent(
    tenant_id: str, agent_id: str, body: AgentIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    rec = await c.catalog.put_agent(p, tenant_id, agent_id, body.base_trust_score, body.allowed_tools, body.owner)
    return rec.model_dump(mode="json")


@router.get("/tenants/{tenant_id}/agents")
async def list_agents(tenant_id: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    return [a.model_dump(mode="json") for a in await c.catalog.list_agents(p, tenant_id)]


@router.delete("/tenants/{tenant_id}/agents/{agent_id}", status_code=204)
async def delete_agent(
    tenant_id: str, agent_id: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    await c.catalog.delete_agent(p, tenant_id, agent_id)
    return Response(status_code=204)


@router.put("/tenants/{tenant_id}/actions")
async def put_action(
    tenant_id: str, body: ActionIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    rec = await c.catalog.put_action(p, tenant_id, body.action, body.resource_pattern, body.base_risk_score)
    return rec.model_dump(mode="json")


@router.get("/tenants/{tenant_id}/actions")
async def list_actions(tenant_id: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    return [a.model_dump(mode="json") for a in await c.catalog.list_actions(p, tenant_id)]


@router.delete("/tenants/{tenant_id}/actions/{action_id}", status_code=204)
async def delete_action(
    tenant_id: str, action_id: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    await c.catalog.delete_action(p, tenant_id, action_id)
    return Response(status_code=204)


@router.put("/tenants/{tenant_id}/modifiers")
async def put_modifier(
    tenant_id: str, body: ModifierIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return (await c.catalog.put_modifier(p, tenant_id, body.kind, body.value, body.delta)).model_dump(mode="json")


@router.get("/tenants/{tenant_id}/modifiers")
async def list_modifiers(tenant_id: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    return [m.model_dump(mode="json") for m in await c.catalog.list_modifiers(p, tenant_id)]


@router.delete("/tenants/{tenant_id}/modifiers/{modifier_id}", status_code=204)
async def delete_modifier(
    tenant_id: str, modifier_id: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    await c.catalog.delete_modifier(p, tenant_id, modifier_id)
    return Response(status_code=204)


@router.get("/catalog/current")
async def current_catalog(p: Principal = Depends(principal), c: Container = Depends(container)):
    p.require(Permission.READ, p.tenant_id)
    current = await c.catalog.current_document()
    if current is None:
        return {"version": None, "tenants": []}
    doc, _ = current
    tenants = [t for t in doc["tenants"] if p.visible_tenant(t["id"])]
    for t in tenants:
        t["api_keys"] = [{k: v for k, v in key.items() if k != "key_hash"} for key in t["api_keys"]]
    return {**doc, "tenants": tenants}
