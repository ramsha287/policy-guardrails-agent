"""PostgreSQL-backed scoring catalog (agent_profiles, action_catalog, score_modifiers)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.context.catalog import ActionRule, AgentInfo, TenantCatalog
from app.db.models import ActionCatalogEntry, AgentProfile, ScoreModifier


class PgCatalogStore:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sm = sessionmaker

    async def load(self, tenant_id: str) -> TenantCatalog:
        cat = TenantCatalog()
        async with self._sm() as s:
            for a in (await s.execute(select(AgentProfile).where(AgentProfile.tenant_id == tenant_id))).scalars():
                cat.agents[a.agent_id] = AgentInfo(a.agent_id, a.base_trust_score, tuple(a.allowed_tools or ()))
            rows = await s.execute(select(ActionCatalogEntry).where(ActionCatalogEntry.tenant_id == tenant_id))
            for r in rows.scalars():
                cat.actions.setdefault(r.action, []).append(ActionRule(r.action, r.resource_pattern, r.base_risk_score))
            for m in (await s.execute(select(ScoreModifier).where(ScoreModifier.tenant_id == tenant_id))).scalars():
                cat.modifiers[(m.kind, m.value)] = m.delta
        return cat
