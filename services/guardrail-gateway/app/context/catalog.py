"""Scoring catalog: agent profiles (base trust), action catalog (base risk), score modifiers."""

from __future__ import annotations

import asyncio
import fnmatch
import time
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class AgentInfo:
    agent_id: str
    base_trust_score: int
    allowed_tools: tuple[str, ...]


@dataclass(frozen=True)
class ActionRule:
    action: str
    resource_pattern: str
    base_risk_score: int

    @property
    def specificity(self) -> tuple[int, int]:
        """Exact patterns beat wildcards; longer literal prefixes beat shorter ones."""
        wildcard = any(ch in self.resource_pattern for ch in "*?[")
        literal = len(self.resource_pattern.split("*")[0])
        return (0 if wildcard else 1, literal)


@dataclass
class TenantCatalog:
    agents: dict[str, AgentInfo] = field(default_factory=dict)
    actions: dict[str, list[ActionRule]] = field(default_factory=dict)
    modifiers: dict[tuple[str, str], int] = field(default_factory=dict)

    def agent(self, agent_id: str) -> AgentInfo | None:
        return self.agents.get(agent_id)

    def action_rule(self, action: str, resource: str | None) -> ActionRule | None:
        candidates = [
            r for r in self.actions.get(action, []) if fnmatch.fnmatchcase(resource or "", r.resource_pattern)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda r: r.specificity)

    def modifier(self, kind: str, value: str) -> int:
        return self.modifiers.get((kind, value), 0)


class CatalogStore(Protocol):
    async def load(self, tenant_id: str) -> TenantCatalog: ...


class CachedCatalog:
    """Per-tenant catalog cached for `ttl_seconds`; one loader per tenant at a time."""

    def __init__(self, store: CatalogStore, ttl_seconds: int = 30) -> None:
        self._store = store
        self._ttl = ttl_seconds
        self._cache: dict[str, tuple[float, TenantCatalog]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def get(self, tenant_id: str) -> TenantCatalog:
        now = time.monotonic()
        hit = self._cache.get(tenant_id)
        if hit and hit[0] > now:
            return hit[1]
        lock = self._locks.setdefault(tenant_id, asyncio.Lock())
        async with lock:
            hit = self._cache.get(tenant_id)
            if hit and hit[0] > time.monotonic():
                return hit[1]
            cat = await self._store.load(tenant_id)
            self._cache[tenant_id] = (time.monotonic() + self._ttl, cat)
            return cat
