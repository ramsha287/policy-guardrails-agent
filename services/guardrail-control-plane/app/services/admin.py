"""Admin API keys (control-plane access). Stored as SHA-256 hashes; shown once on creation."""

from __future__ import annotations

import hashlib
import secrets

from ..domain.rbac import ROLES, Permission, Principal
from ..domain.records import AdminKeyRecord
from ..errors import NotFound, ValidationFailed
from .context import Ctx

ADMIN_KEY_PREFIX = "cpk_"


def hash_admin_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AdminKeyService:
    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx
        self.store = ctx.store

    async def authenticate(self, raw: str | None) -> Principal | None:
        if not raw or len(raw) > 256:
            return None
        key = await self.store.find_admin_key(hash_admin_key(raw))
        if key is None or not key.is_active:
            return None
        return Principal(key_id=key.id, name=key.name, roles=frozenset(key.roles), tenant_id=key.tenant_id)

    async def create(
        self, p: Principal | None, name: str, roles: list[str], tenant_id: str | None = None, raw: str | None = None
    ) -> tuple[AdminKeyRecord, str]:
        """`p=None` only for bootstrap (CLI). A tenant admin can only mint keys for its tenant."""
        unknown = set(roles) - ROLES
        if unknown or not roles:
            raise ValidationFailed(f"unknown roles {sorted(unknown)}; valid: {sorted(ROLES)}")
        if p is not None:
            p.require(Permission.ADMIN_KEYS, tenant_id)
            if not p.is_platform and tenant_id != p.tenant_id:
                raise ValidationFailed("tenant admins can only create keys for their own tenant")
            if not p.is_platform and "admin" in roles and tenant_id is None:
                raise ValidationFailed("only platform admins can create platform keys")
        raw = raw or ADMIN_KEY_PREFIX + secrets.token_urlsafe(32)
        key = AdminKeyRecord(name=name, key_hash=hash_admin_key(raw), prefix=raw[:12], roles=roles, tenant_id=tenant_id)
        await self.store.add_admin_key(key)
        await self.ctx.log(
            "admin_key", key.id, "create", p.actor if p else "bootstrap", after={"roles": roles, "tenant_id": tenant_id}
        )
        return key, raw

    async def revoke(self, p: Principal, key_id: str) -> None:
        for key in await self.store.list_admin_keys():
            if key.id == key_id:
                p.require(Permission.ADMIN_KEYS, key.tenant_id)
                await self.store.put_admin_key(key.model_copy(update={"is_active": False}))
                await self.ctx.log("admin_key", key_id, "revoke", p.actor)
                return
        raise NotFound(f"admin key {key_id} not found")

    async def list(self, p: Principal) -> list[AdminKeyRecord]:
        p.require(Permission.ADMIN_KEYS, p.tenant_id)
        keys = await self.store.list_admin_keys()
        return [k for k in keys if p.is_platform or k.tenant_id == p.tenant_id]
