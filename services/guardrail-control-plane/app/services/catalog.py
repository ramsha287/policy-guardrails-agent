"""Tenants, gateway API keys, agent profiles, action catalog and score modifiers.

Every change republishes the catalog document right away (no approval step), so a revoked key
or a lowered trust score reaches the gateways within seconds.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from pydantic import ValidationError

from ..domain.compiler import build_catalog, catalog_content_hash, catalog_version, etag
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
from ..errors import NotFound, ValidationFailed
from ..events import CATALOG_CHANNEL
from ..store.base import Conflict
from .context import Ctx

GATEWAY_KEY_PREFIX = "gk_"
BOUND_KEYS_CAPABILITY = "agent_bound_keys"  # reported in gateway heartbeats from 0.6
ADVISORS_CAPABILITY = "advisors_v1"  # reported from 0.9: gateways that read the tenant advisor policy
BINDING_GATEWAY_WINDOW_MINUTES = 15  # gateways heard from this recently must support bound keys


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
        published_at = utcnow()
        if current is not None and published_at <= current.published_at:  # coarse clocks (Windows)
            published_at = current.published_at + timedelta(microseconds=1)
        doc = doc.model_copy(update={"version": catalog_version(published_at, digest), "published_at": published_at})
        record = CatalogRecord(
            version=doc.version,
            document=doc.model_dump(mode="json"),
            etag=etag(digest),
            content_hash=digest,
            published_at=published_at,
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
        rate_limit_per_minute: int | None = None,
        agent_id: str | None = None,
    ) -> tuple[ApiKeyRecord, str]:
        p.require(Permission.CATALOG_WRITE, tenant_id)
        await self._tenant(tenant_id)
        if agent_id is not None:
            await self._require_agent(tenant_id, agent_id)
            await self._require_binding_support()
        raw = GATEWAY_KEY_PREFIX + secrets.token_urlsafe(32)
        key = ApiKeyRecord(
            tenant_id=tenant_id,
            name=name,
            key_hash=hash_key(raw),
            prefix=raw[:12],
            scopes=scopes or ["guard:invoke"],
            environments=list(environments) if environments is not None else None,  # type: ignore[arg-type]
            expires_at=expires_at,
            rate_limit_per_minute=rate_limit_per_minute,
            agent_id=agent_id,
        )
        await self.store.add_api_key(key)
        await self.ctx.log(
            "api_key", key.id, "create", p.actor, after={"tenant_id": tenant_id, "name": name, "agent_id": agent_id}
        )
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

    async def set_api_key_rate_limit(
        self, p: Principal, tenant_id: str, key_id: str, rate_limit_per_minute: int | None
    ) -> ApiKeyRecord:
        """None = the gateway default; 0 = unlimited for this key."""
        p.require(Permission.CATALOG_WRITE, tenant_id)
        key = await self.store.get_api_key(key_id)
        if key is None or key.tenant_id != tenant_id:
            raise NotFound(f"api key {key_id} not found")
        updated = key.model_copy(update={"rate_limit_per_minute": rate_limit_per_minute})
        await self.store.put_api_key(updated)
        await self.ctx.log(
            "api_key",
            key_id,
            "rate_limit",
            p.actor,
            before={"rate_limit_per_minute": key.rate_limit_per_minute},
            after={"rate_limit_per_minute": rate_limit_per_minute},
        )
        await self.publish()
        return updated

    async def _require_binding_support(self) -> None:
        """Gateways older than 0.6 reject a catalog that contains a bound key (and then keep serving
        their last good catalog, missing later revocations). Refuse to bind while one is live."""
        await self._require_capability(BOUND_KEYS_CAPABILITY, "0.6", "binding keys to agents", "bound keys")

    async def _require_capability(self, capability: str, version: str, action: str, feature: str) -> None:
        recent = utcnow() - timedelta(minutes=BINDING_GATEWAY_WINDOW_MINUTES)
        old = [
            g.gateway_id
            for g in await self.store.list_gateways()
            if g.last_seen >= recent and capability not in g.capabilities
        ]
        if old:
            raise ValidationFailed(
                f"upgrade these gateways to {version} or later before {action} "
                f"(older gateways can't read {feature}): {', '.join(sorted(old))}"
            )

    async def set_advisor_policy(self, p: Principal, tenant_id: str, data_classes: Sequence[str]) -> TenantRecord:
        """Which data classes hosted advisors (a vendor classifier, an LLM judge) may see for this
        tenant. Opt-in per class; the tenant's own admins decide. Empty turns hosted advisors off."""
        p.require(Permission.CATALOG_WRITE, tenant_id)
        tenant = await self._tenant(tenant_id)
        classes = sorted(set(data_classes))
        if classes and not tenant.advisor_data_classes:
            await self._require_capability(ADVISORS_CAPABILITY, "0.9", "allowing hosted advisors", "advisor policies")
        try:
            updated = TenantRecord.model_validate({**tenant.model_dump(), "advisor_data_classes": classes})
        except ValidationError as exc:
            raise ValidationFailed("unknown data class", errors=[str(e.get("msg")) for e in exc.errors()]) from exc
        await self.store.put_tenant(updated)
        await self.ctx.log(
            "tenant",
            tenant_id,
            "advisor_policy",
            p.actor,
            before={"advisor_data_classes": tenant.advisor_data_classes},
            after={"advisor_data_classes": classes},
        )
        await self.publish()
        return updated

    async def _require_agent(self, tenant_id: str, agent_id: str) -> None:
        if await self.store.get_agent(tenant_id, agent_id) is None:
            raise ValidationFailed(f"agent {agent_id!r} is not registered in tenant {tenant_id!r}; register it first")

    async def bind_api_key(self, p: Principal, tenant_id: str, key_id: str, agent_id: str | None) -> ApiKeyRecord:
        """Bind a key to one agent (identity assurance A1), or unbind it (None, back to A0).

        Binding is how a legacy key is upgraded; unbinding weakens identity, so it is logged as such.
        """
        p.require(Permission.CATALOG_WRITE, tenant_id)
        key = await self.store.get_api_key(key_id)
        if key is None or key.tenant_id != tenant_id:
            raise NotFound(f"api key {key_id} not found")
        if not key.is_active:
            raise ValidationFailed("this key is revoked")
        if agent_id is not None:
            await self._require_agent(tenant_id, agent_id)
            await self._require_binding_support()
        updated = key.model_copy(update={"agent_id": agent_id})
        await self.store.put_api_key(updated)
        await self.ctx.log(
            "api_key",
            key_id,
            "bind" if agent_id else "unbind",
            p.actor,
            before={"agent_id": key.agent_id},
            after={"agent_id": agent_id},
        )
        await self.publish()
        return updated

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
