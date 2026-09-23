"""Tenants, gateway API keys, agent profiles, action catalog and score modifiers.

Every change republishes the catalog document right away (no approval step), so a revoked key
or a lowered trust score reaches the gateways within seconds.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from ..domain.compiler import build_catalog, catalog_content_hash, etag
from ..domain.rbac import Permission, Principal
from ..domain.records import (
    ActionRecord,
    AgentRecord,
    ApiKeyRecord,
    CatalogRecord,
    ModifierRecord,
    TenantRecord,
    utcnow,
)
from ..errors import NotFound
from ..events import CATALOG_CHANNEL
from ..store.base import Conflict
from .context import Ctx

GATEWAY_KEY_PREFIX = "gk_"


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class CatalogService:
    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx
        self.store = ctx.store

    async def _tenant(self, tenant_id: str) -> TenantRecord:
        t = await self.store.get_tenant(tenant_id)
        if t is None:
            raise NotFound(f"tenant {tenant_id} not found")
        return t

    # ---- publish -----------------------------------------------------------------------

    async def publish(self) -> CatalogRecord:
        """Rebuild the catalog; store a new version only if the content changed."""
        doc = build_catalog(
            await self.store.list_tenants(),
            await self.store.list_api_keys(),
            await self.store.list_agents(),
            await self.store.list_actions(),
            await self.store.list_modifiers(),
        )
        digest = catalog_content_hash(doc)
        current = await self.store.current_catalog()
        if current is not None and current.content_hash == digest:
            return current
        doc = doc.model_copy(update={"published_at": utcnow()})
        record = CatalogRecord(
            version=doc.version, document=doc.model_dump(mode="json"), etag=etag(digest), content_hash=digest
        )
        await self.store.add_catalog(record)
        await self.ctx.events.publish(CATALOG_CHANNEL, {"version": record.version})
        return record

    # ---- tenants -------------------------------------------------------------------------

    async def create_tenant(self, p: Principal, tenant_id: str, name: str) -> TenantRecord:
        p.require(Permission.CATALOG_WRITE)  # tenant_id=None: only platform keys may create tenants
        tenant = TenantRecord(id=tenant_id, name=name)
        async with self.store.transaction():
            if await self.store.get_tenant(tenant_id) is not None:
                raise Conflict(f"tenant {tenant_id} exists")
            await self.store.put_tenant(tenant)
            await self.ctx.log("tenant", tenant_id, "create", p.actor, after=tenant.model_dump(mode="json"))
        await self.publish()
        return tenant

    async def set_tenant_status(self, p: Principal, tenant_id: str, status: str) -> TenantRecord:
        p.require(Permission.CATALOG_WRITE)  # suspending a tenant is a platform decision
        tenant = await self._tenant(tenant_id)
        updated = tenant.model_copy(update={"status": status})
        await self.store.put_tenant(updated)
        await self.ctx.log("tenant", tenant_id, f"status:{status}", p.actor, before={"status": tenant.status})
        await self.publish()
        return updated

    async def list_tenants(self, p: Principal) -> list[TenantRecord]:
        p.require(Permission.READ, p.tenant_id)
        return [t for t in await self.store.list_tenants() if p.visible_tenant(t.id)]

    # ---- gateway API keys ----------------------------------------------------------------

    async def create_api_key(
        self,
        p: Principal,
        tenant_id: str,
        name: str,
        scopes: list[str] | None = None,
        environments: Sequence[str] | None = None,
        expires_at: datetime | None = None,
    ) -> tuple[ApiKeyRecord, str]:
        p.require(Permission.CATALOG_WRITE, tenant_id)
        await self._tenant(tenant_id)
        raw = GATEWAY_KEY_PREFIX + secrets.token_urlsafe(32)
        key = ApiKeyRecord(
            tenant_id=tenant_id,
            name=name,
            key_hash=hash_key(raw),
            prefix=raw[:12],
            scopes=scopes or ["guard:invoke"],
            environments=list(environments) if environments is not None else None,  # type: ignore[arg-type]
            expires_at=expires_at,
        )
        await self.store.add_api_key(key)
        await self.ctx.log("api_key", key.id, "create", p.actor, after={"tenant_id": tenant_id, "name": name})
        await self.publish()
        return key, raw

    async def import_api_key(self, p: Principal, key: ApiKeyRecord) -> None:
        """Import an existing key by hash (migration from the gateway's own tables)."""
        p.require(Permission.CATALOG_WRITE, key.tenant_id)
        existing = [k for k in await self.store.list_api_keys(key.tenant_id) if k.key_hash == key.key_hash]
        if not existing:
            await self.store.add_api_key(key)
            await self.ctx.log("api_key", key.id, "import", p.actor, after={"tenant_id": key.tenant_id})

    async def list_api_keys(self, p: Principal, tenant_id: str) -> list[ApiKeyRecord]:
        p.require(Permission.READ, tenant_id)
        return await self.store.list_api_keys(tenant_id)

    async def revoke_api_key(self, p: Principal, tenant_id: str, key_id: str) -> ApiKeyRecord:
        p.require(Permission.CATALOG_WRITE, tenant_id)
        key = await self.store.get_api_key(key_id)
        if key is None or key.tenant_id != tenant_id:
            raise NotFound(f"api key {key_id} not found")
        revoked = key.model_copy(update={"is_active": False, "revoked_at": utcnow()})
        await self.store.put_api_key(revoked)
        await self.ctx.log("api_key", key_id, "revoke", p.actor)
        await self.publish()
        return revoked

    # ---- agents / actions / modifiers ----------------------------------------------------

    async def put_agent(
        self, p: Principal, tenant_id: str, agent_id: str, base_trust_score: int, allowed_tools: list[str], owner=None
    ) -> AgentRecord:
        p.require(Permission.CATALOG_WRITE, tenant_id)
        await self._tenant(tenant_id)
        before = await self.store.get_agent(tenant_id, agent_id)
        agent = AgentRecord(
            tenant_id=tenant_id,
            agent_id=agent_id,
            base_trust_score=base_trust_score,
            allowed_tools=allowed_tools,
            owner=owner,
        )
        await self.store.put_agent(agent)
        await self.ctx.log(
            "agent",
            f"{tenant_id}/{agent_id}",
            "upsert",
            p.actor,
            before=before.model_dump(mode="json") if before else None,
            after=agent.model_dump(mode="json"),
        )
        await self.publish()
        return agent

    async def delete_agent(self, p: Principal, tenant_id: str, agent_id: str) -> None:
        p.require(Permission.CATALOG_WRITE, tenant_id)
        if not await self.store.delete_agent(tenant_id, agent_id):
            raise NotFound(f"agent {agent_id} not found")
        await self.ctx.log("agent", f"{tenant_id}/{agent_id}", "delete", p.actor)
        await self.publish()

    async def list_agents(self, p: Principal, tenant_id: str) -> list[AgentRecord]:
        p.require(Permission.READ, tenant_id)
        return await self.store.list_agents(tenant_id)

    async def put_action(
        self, p: Principal, tenant_id: str, action: str, resource_pattern: str, base_risk_score: int
    ) -> ActionRecord:
        p.require(Permission.CATALOG_WRITE, tenant_id)
        await self._tenant(tenant_id)
        rec = await self.store.put_action(
            ActionRecord(
                tenant_id=tenant_id, action=action, resource_pattern=resource_pattern, base_risk_score=base_risk_score
            )
        )
        await self.ctx.log("action", rec.id, "upsert", p.actor, after=rec.model_dump(mode="json"))
        await self.publish()
        return rec

    async def delete_action(self, p: Principal, tenant_id: str, action_id: str) -> None:
        p.require(Permission.CATALOG_WRITE, tenant_id)
        if not await self.store.delete_action(tenant_id, action_id):
            raise NotFound(f"action {action_id} not found")
        await self.ctx.log("action", action_id, "delete", p.actor)
        await self.publish()

    async def list_actions(self, p: Principal, tenant_id: str) -> list[ActionRecord]:
        p.require(Permission.READ, tenant_id)
        return await self.store.list_actions(tenant_id)

    async def put_modifier(self, p: Principal, tenant_id: str, kind: str, value: str, delta: int) -> ModifierRecord:
        p.require(Permission.CATALOG_WRITE, tenant_id)
        await self._tenant(tenant_id)
        rec = await self.store.put_modifier(
            ModifierRecord(tenant_id=tenant_id, kind=kind, value=value, delta=delta)  # type: ignore[arg-type]
        )
        await self.ctx.log("modifier", rec.id, "upsert", p.actor, after=rec.model_dump(mode="json"))
        await self.publish()
        return rec

    async def delete_modifier(self, p: Principal, tenant_id: str, modifier_id: str) -> None:
        p.require(Permission.CATALOG_WRITE, tenant_id)
        if not await self.store.delete_modifier(tenant_id, modifier_id):
            raise NotFound(f"modifier {modifier_id} not found")
        await self.ctx.log("modifier", modifier_id, "delete", p.actor)
        await self.publish()

    async def list_modifiers(self, p: Principal, tenant_id: str) -> list[ModifierRecord]:
        p.require(Permission.READ, tenant_id)
        return await self.store.list_modifiers(tenant_id)

    async def current_document(self) -> tuple[dict[str, Any], str] | None:
        rec = await self.store.current_catalog()
        return (rec.document, rec.etag) if rec else None
