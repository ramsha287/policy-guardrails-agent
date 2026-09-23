"""In-memory Store for tests and local experiments. Not for production."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TypeVar, overload

from pydantic import BaseModel

from ..domain.records import (
    ActionRecord,
    AdminKeyRecord,
    AgentRecord,
    ApiKeyRecord,
    AssignmentRecord,
    CatalogRecord,
    ChangeRecord,
    GatewayRecord,
    GuardrailVersionRecord,
    ModifierRecord,
    PublishRequestRecord,
    ReviewRecord,
    SnapshotRecord,
    TenantRecord,
)
from .base import Conflict

M = TypeVar("M", bound=BaseModel)


@overload
def _copy(r: M) -> M: ...
@overload
def _copy(r: M | None) -> M | None: ...
def _copy(r: M | None) -> M | None:  # never hand out the stored instance
    return r.model_copy(deep=True) if r is not None else None


class MemoryStore:
    def __init__(self) -> None:
        self.tenants: dict[str, TenantRecord] = {}
        self.api_keys: dict[str, ApiKeyRecord] = {}
        self.agents: dict[tuple[str, str], AgentRecord] = {}
        self.actions: dict[str, ActionRecord] = {}
        self.modifiers: dict[str, ModifierRecord] = {}
        self.versions: dict[tuple[str, str], GuardrailVersionRecord] = {}
        self.assignments: dict[tuple[str, str], AssignmentRecord] = {}
        self.snapshots: dict[str, SnapshotRecord] = {}
        self.current: dict[str, str] = {}
        self.catalogs: list[CatalogRecord] = []
        self.publish_requests: dict[str, PublishRequestRecord] = {}
        self.reviews: dict[str, ReviewRecord] = {}
        self.admin_keys: dict[str, AdminKeyRecord] = {}
        self.gateways: dict[str, GatewayRecord] = {}
        self.changes: list[ChangeRecord] = []
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        async with self._lock:
            yield

    # tenants
    async def get_tenant(self, tenant_id):
        return _copy(self.tenants.get(tenant_id))

    async def list_tenants(self):
        return [_copy(t) for t in sorted(self.tenants.values(), key=lambda t: t.id)]

    async def put_tenant(self, tenant):
        self.tenants[tenant.id] = _copy(tenant)

    # api keys
    async def add_api_key(self, key):
        if any(k.key_hash == key.key_hash for k in self.api_keys.values()):
            raise Conflict("duplicate key hash")
        self.api_keys[key.id] = _copy(key)

    async def get_api_key(self, key_id):
        return _copy(self.api_keys.get(key_id))

    async def list_api_keys(self, tenant_id=None):
        return [_copy(k) for k in self.api_keys.values() if tenant_id is None or k.tenant_id == tenant_id]

    async def put_api_key(self, key):
        self.api_keys[key.id] = _copy(key)

    # agents / actions / modifiers
    async def put_agent(self, agent):
        self.agents[(agent.tenant_id, agent.agent_id)] = _copy(agent)

    async def get_agent(self, tenant_id, agent_id):
        return _copy(self.agents.get((tenant_id, agent_id)))

    async def list_agents(self, tenant_id=None):
        return [_copy(a) for a in self.agents.values() if tenant_id is None or a.tenant_id == tenant_id]

    async def delete_agent(self, tenant_id, agent_id):
        return self.agents.pop((tenant_id, agent_id), None) is not None

    async def put_action(self, action):
        for existing in self.actions.values():
            same = (existing.tenant_id, existing.action, existing.resource_pattern)
            if same == (action.tenant_id, action.action, action.resource_pattern):
                action = action.model_copy(update={"id": existing.id})
        self.actions[action.id] = _copy(action)
        return _copy(action)

    async def list_actions(self, tenant_id=None):
        return [_copy(a) for a in self.actions.values() if tenant_id is None or a.tenant_id == tenant_id]

    async def delete_action(self, tenant_id, action_id):
        a = self.actions.get(action_id)
        if a is None or a.tenant_id != tenant_id:
            return False
        del self.actions[action_id]
        return True

    async def put_modifier(self, modifier):
        for existing in self.modifiers.values():
            if (existing.tenant_id, existing.kind, existing.value) == (
                modifier.tenant_id,
                modifier.kind,
                modifier.value,
            ):
                modifier = modifier.model_copy(update={"id": existing.id})
        self.modifiers[modifier.id] = _copy(modifier)
        return _copy(modifier)

    async def list_modifiers(self, tenant_id=None):
        return [_copy(m) for m in self.modifiers.values() if tenant_id is None or m.tenant_id == tenant_id]

    async def delete_modifier(self, tenant_id, modifier_id):
        m = self.modifiers.get(modifier_id)
        if m is None or m.tenant_id != tenant_id:
            return False
        del self.modifiers[modifier_id]
        return True

    # registry
    async def put_version(self, version):
        self.versions[(version.guardrail_id, version.version)] = _copy(version)

    async def get_version(self, guardrail_id, version):
        return _copy(self.versions.get((guardrail_id, version)))

    async def list_versions(self, guardrail_id=None):
        return [_copy(v) for k, v in sorted(self.versions.items()) if guardrail_id is None or k[0] == guardrail_id]

    # assignments
    async def put_assignment(self, record):
        self.assignments[(record.environment, record.assignment.id)] = _copy(record)

    async def get_assignment(self, environment, assignment_id):
        return _copy(self.assignments.get((environment, assignment_id)))

    async def list_assignments(self, environment):
        return [
            _copy(r)
            for (env, _), r in sorted(self.assignments.items(), key=lambda kv: (kv[1].assignment.order, kv[0][1]))
            if env == environment
        ]

    async def delete_assignment(self, environment, assignment_id):
        return self.assignments.pop((environment, assignment_id), None) is not None

    async def replace_assignments(self, environment, records):
        for key in [k for k in self.assignments if k[0] == environment]:
            del self.assignments[key]
        for r in records:
            await self.put_assignment(r)

    # snapshots
    async def add_snapshot(self, snapshot):
        if any(
            s.environment == snapshot.environment and s.version == snapshot.version for s in self.snapshots.values()
        ):
            raise Conflict("snapshot version exists")
        self.snapshots[snapshot.id] = _copy(snapshot)

    async def get_snapshot(self, environment, version):
        for s in self.snapshots.values():
            if s.environment == environment and s.version == version:
                return _copy(s)
        return None

    async def current_snapshot(self, environment):
        sid = self.current.get(environment)
        return _copy(self.snapshots.get(sid)) if sid else None

    async def set_current_snapshot(self, environment, snapshot_id):
        self.current[environment] = snapshot_id

    async def list_snapshots(self, environment, limit=50):
        items = [s for s in self.snapshots.values() if s.environment == environment]
        return [_copy(s) for s in sorted(items, key=lambda s: s.published_at, reverse=True)[:limit]]

    async def count_snapshots(self, environment):
        return sum(1 for s in self.snapshots.values() if s.environment == environment)

    # catalog
    async def add_catalog(self, catalog):
        self.catalogs.append(_copy(catalog))

    async def current_catalog(self):
        return _copy(self.catalogs[-1]) if self.catalogs else None

    # publish requests
    async def add_publish_request(self, request):
        self.publish_requests[request.id] = _copy(request)

    async def get_publish_request(self, request_id):
        return _copy(self.publish_requests.get(request_id))

    async def put_publish_request(self, request):
        self.publish_requests[request.id] = _copy(request)

    async def list_publish_requests(self, environment=None, status=None):
        return [
            _copy(r)
            for r in sorted(self.publish_requests.values(), key=lambda r: r.requested_at, reverse=True)
            if (environment is None or r.environment == environment) and (status is None or r.status == status)
        ]

    # reviews
    async def add_review(self, review):
        self.reviews[review.id] = _copy(review)

    async def get_review(self, review_id):
        return _copy(self.reviews.get(review_id))

    async def put_review(self, review):
        self.reviews[review.id] = _copy(review)

    async def list_reviews(self, tenant_id=None, status=None, limit=100):
        items = [
            r
            for r in self.reviews.values()
            if (tenant_id is None or r.tenant_id == tenant_id) and (status is None or r.status == status)
        ]
        return [_copy(r) for r in sorted(items, key=lambda r: r.created_at, reverse=True)[:limit]]

    # admin keys
    async def add_admin_key(self, key):
        self.admin_keys[key.id] = _copy(key)

    async def find_admin_key(self, key_hash):
        for k in self.admin_keys.values():
            if k.key_hash == key_hash:
                return _copy(k)
        return None

    async def list_admin_keys(self):
        return [_copy(k) for k in self.admin_keys.values()]

    async def put_admin_key(self, key):
        self.admin_keys[key.id] = _copy(key)

    # gateways
    async def put_gateway(self, gateway):
        self.gateways[gateway.gateway_id] = _copy(gateway)

    async def list_gateways(self, environment=None):
        return [_copy(g) for g in self.gateways.values() if environment is None or g.environment == environment]

    # change log
    async def log_change(self, change):
        self.changes.append(change.model_copy(update={"id": len(self.changes) + 1}))

    async def list_changes(self, entity=None, entity_id=None, limit=100):
        items = [
            c
            for c in reversed(self.changes)
            if (entity is None or c.entity == entity) and (entity_id is None or c.entity_id == entity_id)
        ]
        return [_copy(c) for c in items[:limit]]
