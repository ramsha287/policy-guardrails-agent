"""PostgreSQL-backed API key store (guardrail.api_keys + guardrail.tenants)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import GatewayApiKey, Tenant
from app.gateway.auth import Principal


class PgApiKeyStore:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sm = sessionmaker

    async def lookup(self, key_hash: str) -> Principal | None:
        now = datetime.now(UTC)
        async with self._sm() as s:
            row = (
                await s.execute(
                    select(GatewayApiKey, Tenant.status)
                    .join(Tenant, Tenant.id == GatewayApiKey.tenant_id)
                    .where(GatewayApiKey.key_hash == key_hash, GatewayApiKey.is_active.is_(True))
                )
            ).first()
        if row is None:
            return None
        key, tenant_status = row
        if tenant_status != "active":
            return None
        if key.expires_at is not None and key.expires_at <= now:
            return None
        return Principal(str(key.id), key.tenant_id, key.name, frozenset(key.scopes or []))
