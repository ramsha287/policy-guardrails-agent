"""Agent discovery: connectors, runs, the inventory and what operators do with it.

connectors   platform admins configure sources (discovery:write); they run on a schedule or on
             demand ("sync now"), one at a time per connector across all replicas (a lease)
inventory    entities with state (managed / registered_unmanaged / shadow / stale), evidence,
             a temporal relation graph, coverage, and findings
actions      tenant editors link an entity to a registered agent, register it (creates the
             registry entry), ignore it for a while, and accept or resolve findings
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from pydantic import ValidationError

from ..discovery import classify
from ..discovery.model import CollectContext, Fetch, Resolver
from ..discovery.pipeline import DEFAULT_MAX_OBSERVATIONS, DiscoveryPipeline, observed_by_connector
from ..discovery.registry import describe as describe_kinds
from ..discovery.registry import get as get_kind
from ..discovery.safety import secret_reader, url_checker
from ..domain.inventory import (
    ENTITY_STATES,
    OBSERVATION_RETENTION_DAYS,
    ConnectorRecord,
    EntityRecord,
    FindingRecord,
    SyncRunRecord,
)
from ..domain.rbac import Permission, Principal
from ..domain.records import ENVIRONMENTS, utcnow
from ..errors import NotFound, StateConflict, ValidationFailed
from ..metrics import DISCOVERY_RUNS
from .catalog import CatalogService
from .context import Ctx

logger = logging.getLogger(__name__)

LEASE = timedelta(minutes=30)
MAX_GRAPH_NODES = 300


class DiscoveryService:
    def __init__(
        self,
        ctx: Ctx,
        http: httpx.AsyncClient,
        *,
        audit_fetch: Fetch | None = None,
        catalog: CatalogService | None = None,
        allow_http: bool = False,
        max_observations: int = DEFAULT_MAX_OBSERVATIONS,
        clients: Mapping[str, Any] | None = None,
        secret_env: Mapping[str, str] | None = None,
        resolver: Resolver | None = None,
        clock: Any = utcnow,
    ) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.http = http
        self.audit_fetch = audit_fetch
        self.catalog = catalog or CatalogService(ctx)
        self.clients = dict(clients or {})
        self.secrets = secret_reader(secret_env)
        self.check_url = url_checker(resolver, allow_http=allow_http)
        self.now = clock
        self.pipeline = DiscoveryPipeline(ctx.store, ctx.events, clock=clock, max_observations=max_observations)
        self.instance = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"

    # ---- connectors ----------------------------------------------------------------------------

    @staticmethod
    def kinds() -> list[dict[str, Any]]:
        return describe_kinds()

    async def _tenant(self, tenant_id: str) -> None:
        if await self.store.get_tenant(tenant_id) is None:
            raise NotFound(f"tenant {tenant_id} not found")

    async def _connector(self, tenant_id: str, connector_id: str) -> ConnectorRecord:
        c = await self.store.get_connector(connector_id)
        if c is None or c.tenant_id != tenant_id:
            raise NotFound(f"connector {connector_id} not found")
        return c

    @staticmethod
    def _validated(kind: str, config: dict[str, Any]) -> dict[str, Any]:
        impl = get_kind(kind)
        if impl is None:
            raise ValidationFailed(f"unknown connector kind {kind!r}", errors=["see GET /inv/v1/connector-kinds"])
        try:
            return impl.Config.model_validate(config).model_dump(mode="json")
        except ValidationError as exc:
            errs = [f"{'.'.join(str(p) for p in e.get('loc', []))}: {e.get('msg')}" for e in exc.errors()]
            raise ValidationFailed(f"invalid {kind} configuration", errors=errs) from exc

    @staticmethod
    def _environment(environment: str | None) -> str | None:
        if environment is not None and environment not in ENVIRONMENTS:
            raise ValidationFailed(f"environment must be one of {', '.join(ENVIRONMENTS)}")
        return environment

    @staticmethod
    def _visible(p: Principal, c: ConnectorRecord) -> ConnectorRecord:
        """Configuration (URLs, account ids, secret variable names) is for those who manage it."""
        return c if p.can(Permission.DISCOVERY_WRITE, c.tenant_id) else c.model_copy(update={"config": {}})

    async def list_connectors(self, p: Principal, tenant_id: str) -> list[ConnectorRecord]:
        p.require(Permission.READ, tenant_id)
        return [self._visible(p, c) for c in await self.store.list_connectors(tenant_id)]

    async def get_connector(self, p: Principal, tenant_id: str, connector_id: str) -> ConnectorRecord:
        p.require(Permission.READ, tenant_id)
        return self._visible(p, await self._connector(tenant_id, connector_id))

    async def create_connector(
        self,
        p: Principal,
        tenant_id: str,
        *,
        kind: str,
        name: str,
        config: dict[str, Any],
        environment: str | None = None,
        interval_minutes: int = 60,
        enabled: bool = True,
    ) -> ConnectorRecord:
        p.require(Permission.DISCOVERY_WRITE, tenant_id)
        await self._tenant(tenant_id)
        try:
            c = ConnectorRecord(
                tenant_id=tenant_id,
                kind=kind,
                name=name,
                config=self._validated(kind, config),
                environment=self._environment(environment),
                interval_minutes=interval_minutes,
                enabled=enabled,
                created_by=p.actor,
            )
        except ValidationError as exc:
            raise ValidationFailed("invalid connector", errors=[str(e.get("msg")) for e in exc.errors()]) from exc
        await self.store.put_connector(c)
        await self.ctx.log("connector", c.id, "create", p.actor, after=_public(c))
        return c

    async def update_connector(
        self, p: Principal, tenant_id: str, connector_id: str, changes: dict[str, Any]
    ) -> ConnectorRecord:
        p.require(Permission.DISCOVERY_WRITE, tenant_id)
        c = await self._connector(tenant_id, connector_id)
        update: dict[str, Any] = {}
        if "config" in changes:
            update["config"] = self._validated(c.kind, changes["config"] or {})
        if "environment" in changes:
            update["environment"] = self._environment(changes["environment"])
        for f in ("name", "interval_minutes", "enabled"):
            if f in changes and changes[f] is not None:
                update[f] = changes[f]
        update["updated_at"] = self.now()
        try:
            updated = ConnectorRecord.model_validate({**c.model_dump(), **update})
        except ValidationError as exc:
            raise ValidationFailed("invalid connector", errors=[str(e.get("msg")) for e in exc.errors()]) from exc
        # Only the edited columns: a run finishing meanwhile keeps its lease and outcome.
        await self.store.update_connector_fields(c.id, {k: getattr(updated, k) for k in update})
        await self.ctx.log("connector", c.id, "update", p.actor, before=_public(c), after=_public(updated))
        return updated

    async def delete_connector(self, p: Principal, tenant_id: str, connector_id: str) -> None:
        p.require(Permission.DISCOVERY_WRITE, tenant_id)
        c = await self._connector(tenant_id, connector_id)
        # Its relations stop being current; its evidence (observations, entities) stays.
        async with self.store.tenant_lock(tenant_id):
            for e in await self.store.list_edges(tenant_id, source=connector_id):
                e.valid_to = self.now()
                await self.store.put_edge(e)
            await self.store.delete_connector(connector_id)
        await self.ctx.log("connector", c.id, "delete", p.actor, before=_public(c))

    async def list_runs(self, p: Principal, tenant_id: str, connector_id: str, limit: int = 20) -> list[SyncRunRecord]:
        p.require(Permission.READ, tenant_id)
        await self._connector(tenant_id, connector_id)
        return await self.store.list_runs(connector_id, max(1, min(limit, 100)))

    async def sync(self, p: Principal, tenant_id: str, connector_id: str) -> SyncRunRecord:
        """Run a connector now (any editor of the tenant; the configuration stays platform-only)."""
        p.require(Permission.INVENTORY_WRITE, tenant_id)
        c = await self._connector(tenant_id, connector_id)
        run = await self.run_connector(c, triggered_by=p.actor)
        if run is None:
            raise StateConflict("this connector is already running; try again when it finishes")
        return run

    async def run_connector(
        self, c: ConnectorRecord, *, triggered_by: str, only_if_due: bool = False
    ) -> SyncRunRecord | None:
        """None when another run holds the lease (or, with only_if_due, it is not due any more)."""
        now = self.now()
        if not await self.store.claim_connector(c.id, self.instance, now, now + LEASE, only_if_due=only_if_due):
            return None
        c = await self.store.get_connector(c.id) or c  # the claimed row: config and last run as of now
        run = SyncRunRecord(tenant_id=c.tenant_id, connector_id=c.id, triggered_by=triggered_by, started_at=now)
        await self.store.put_run(run)
        ctx = CollectContext(
            tenant_id=c.tenant_id,
            connector_id=c.id,
            environment=c.environment,
            http=self.http,
            now=now,
            since=c.last_run_at if c.last_status == "ok" else None,
            secrets=self.secrets,
            check_url=self.check_url,
            audit_fetch=self.audit_fetch,
            clients=self.clients,
        )
        try:
            run = await self.pipeline.run(c, ctx, run)
        except Exception as exc:  # noqa: BLE001 - recorded on the run; the lease is always released
            logger.error("discovery run %s failed: %s", run.id, exc.__class__.__name__, exc_info=exc)
            run.status, run.error, run.finished_at = "error", f"internal error: {exc.__class__.__name__}", self.now()
        finally:
            await self.store.put_run(run)
            await self.store.release_connector(
                c.id, self.instance, status=run.status, error=run.error, finished_at=run.finished_at or self.now()
            )
        DISCOVERY_RUNS.labels(c.kind, run.status).inc()
        await self._republish()
        return run

    async def run_due(self) -> int:
        """Scheduler tick: run every enabled connector whose interval has passed. Returns runs started."""
        now = self.now()
        started = 0
        for c in await self.store.list_connectors():
            if not c.enabled:
                continue
            if c.last_run_at is not None and c.last_run_at + timedelta(minutes=c.interval_minutes) > now:
                continue
            if await self.run_connector(c, triggered_by="schedule", only_if_due=True) is not None:
                started += 1
        return started

    async def housekeeping(self) -> int:
        removed = await self.store.prune_observations(self.now() - timedelta(days=OBSERVATION_RETENTION_DAYS))
        for t in await self.store.list_tenants():  # time alone moves agents to stale
            await self.pipeline.reconcile_tenant(t.id)
        await self._republish()
        return removed

    # ---- inventory -----------------------------------------------------------------------------

    async def list_entities(
        self,
        p: Principal,
        tenant_id: str,
        *,
        kind: str | None = None,
        state: str | None = None,
        agents_only: bool = False,
        query: str | None = None,
        limit: int = 500,
    ) -> list[EntityRecord]:
        p.require(Permission.READ, tenant_id)
        if state is not None and state not in ENTITY_STATES:
            raise ValidationFailed(f"state must be one of {', '.join(ENTITY_STATES)}")
        return await self.store.list_entities(
            tenant_id, kind=kind, state=state, agents_only=agents_only, query=query, limit=max(1, min(limit, 2000))
        )

    async def _entity(self, tenant_id: str, entity_id: str) -> EntityRecord:
        e = await self.store.get_entity(tenant_id, entity_id)
        if e is None:
            raise NotFound(f"entity {entity_id} not found")
        return e

    async def get_entity(self, p: Principal, tenant_id: str, entity_id: str) -> dict[str, Any]:
        p.require(Permission.READ, tenant_id)
        e = await self._entity(tenant_id, entity_id)
        evidence = []
        for eid in [e.id, *(e.attrs.get("merged_from") or [])][:20]:
            evidence.extend(await self.store.list_observations(tenant_id, entity_id=eid, limit=50))
        evidence.sort(key=lambda o: o.observed_at, reverse=True)
        edges = await self.store.list_edges(tenant_id, entity_ids=[e.id])
        names = await self._names(tenant_id, {x for edge in edges for x in (edge.src, edge.dst)})
        return {
            "entity": e,
            "evidence": evidence[:50],
            "relations": [
                {
                    "edge": edge,
                    "direction": "out" if edge.src == e.id else "in",
                    "other": names.get(edge.dst if edge.src == e.id else edge.src),
                }
                for edge in edges
            ],
            "findings": await self.store.list_findings(tenant_id, entity_id=e.id),
        }

    async def _names(self, tenant_id: str, ids: set[str]) -> dict[str, dict[str, Any]]:
        out = {}
        for i in ids:
            x = await self.store.get_entity(tenant_id, i)
            if x is not None:
                out[i] = {"id": x.id, "kind": x.kind, "name": x.name, "state": x.state}
        return out

    async def graph(
        self, p: Principal, tenant_id: str, entity_id: str, *, depth: int = 2, as_of: datetime | None = None
    ) -> dict[str, Any]:
        """Neighbourhood of an entity: breadth-first over relations valid now (or `as_of`)."""
        if as_of is not None and as_of.tzinfo is None:
            as_of = as_of.replace(tzinfo=UTC)  # a time without an offset is UTC
        p.require(Permission.READ, tenant_id)
        await self._entity(tenant_id, entity_id)
        depth = max(1, min(depth, 4))
        seen = {entity_id}
        frontier = {entity_id}
        edges: dict[str, Any] = {}
        truncated = False
        for _ in range(depth):
            if not frontier:
                break
            batch = await self.store.list_edges(tenant_id, entity_ids=sorted(frontier), as_of=as_of)
            nxt: set[str] = set()
            for edge in batch:
                edges[edge.id] = edge
                for x in (edge.src, edge.dst):
                    if x not in seen:
                        if len(seen) >= MAX_GRAPH_NODES:
                            truncated = True
                            continue
                        seen.add(x)
                        nxt.add(x)
            frontier = nxt
        nodes = await self._names(tenant_id, seen)
        kept = [e for e in edges.values() if e.src in nodes and e.dst in nodes]
        return {
            "root": entity_id,
            "as_of": as_of,
            "depth": depth,
            "nodes": list(nodes.values()),
            "edges": [
                {
                    "id": e.id,
                    "src": e.src,
                    "dst": e.dst,
                    "kind": e.kind,
                    "valid_from": e.valid_from,
                    "valid_to": e.valid_to,
                    "confidence": e.confidence,
                }
                for e in kept
            ],  # fmt: skip
            "truncated": truncated,
        }

    async def coverage(self, p: Principal, tenant_id: str, environment: str | None = None) -> dict[str, Any]:
        """How much of the agent population (and its traffic) goes through the gateway."""
        p.require(Permission.READ, tenant_id)
        now = self.now()
        agents = [
            e
            for e in await self.store.list_entities(tenant_id, agents_only=True, limit=1_000_000)
            if (environment is None or e.environment == environment) and not e.ignored(now)
        ]
        by_state = {s: 0 for s in ENTITY_STATES if s != "not_agent"}
        for e in agents:
            if e.state in by_state:
                by_state[e.state] += 1
        active = [e for e in agents if e.state != "stale" and observed_by_connector(e)]
        managed = [e for e in active if e.state == "managed"]
        direct_by_unit: dict[str, int] = {}
        for e in active:
            if e.state == "managed" or not e.direct_volume:
                continue
            for entry in (e.attrs.get("by_source") or {}).values():
                unit = (entry.get("attrs") or {}).get("volume_unit", "calls")
                direct_by_unit[unit] = direct_by_unit.get(unit, 0) + int(entry.get("direct") or 0)
        return {
            "tenant_id": tenant_id,
            "environment": environment,
            "agents": len(agents),
            "active_agents": len(active),
            "by_state": by_state,
            "agent_coverage": round(len(managed) / len(active), 4) if active else None,
            "volume": {
                "window_days": 7,
                "gateway_requests": sum(e.managed_volume for e in agents),
                "direct_outside_gateway": direct_by_unit,
            },
            "open_findings": len(await self.store.list_findings(tenant_id, status="open", limit=1_000_000)),
            "connectors": [
                {"id": c.id, "kind": c.kind, "name": c.name, "last_run_at": c.last_run_at, "last_status": c.last_status}
                for c in await self.store.list_connectors(tenant_id)
            ],
        }

    async def link(self, p: Principal, tenant_id: str, entity_id: str, agent_id: str) -> EntityRecord:
        """Say "this is registered agent X" (adds the strong key agent:X; entities that already
        carry it, such as X's own registry entry, are merged into this one)."""
        p.require(Permission.INVENTORY_WRITE, tenant_id)
        e = await self._entity(tenant_id, entity_id)
        if await self.store.get_agent(tenant_id, agent_id) is None:
            raise ValidationFailed(f"agent {agent_id!r} is not registered in tenant {tenant_id!r}")
        if e.kind not in classify.AGENT_CAPABLE:
            raise ValidationFailed(f"a {e.kind} can't be an agent; link the workload or identity that runs it")
        key = f"agent:{agent_id}"
        async with self.store.tenant_lock(tenant_id):
            e = await self._entity(tenant_id, entity_id)  # re-read under the lock
            e.strong_keys = sorted(set(e.strong_keys) | {key})
            links = list(e.attrs.get("manual_links") or [])
            links.append({"agent_id": agent_id, "by": p.actor, "at": self.now().isoformat()})
            e.attrs = {**e.attrs, "manual_links": links[-10:]}
            await self.store.put_entity(e)
            await self.ctx.log("inventory_entity", e.id, "link", p.actor, after={"agent_id": agent_id})
            await self.pipeline.reconcile_tenant(tenant_id)
            merged = await self.store.find_entities(tenant_id, [key])
        await self._republish()
        return merged[0] if merged else await self._entity(tenant_id, entity_id)

    async def register(
        self,
        p: Principal,
        tenant_id: str,
        entity_id: str,
        *,
        agent_id: str,
        base_trust_score: int = 50,
        allowed_tools: list[str] | None = None,
        owner: str | None = None,
    ) -> EntityRecord:
        """Create the registry entry for a discovered agent and link it (shadow -> registered)."""
        p.require(Permission.INVENTORY_WRITE, tenant_id)
        e = await self._entity(tenant_id, entity_id)
        if await self.store.get_agent(tenant_id, agent_id) is not None:
            raise StateConflict(f"agent {agent_id!r} is already registered; link the entity to it instead")
        await self.catalog.put_agent(
            p, tenant_id, agent_id, base_trust_score, allowed_tools or [], owner or e.owner_guess
        )  # requires catalog:write, publishes the catalog
        return await self.link(p, tenant_id, entity_id, agent_id)

    async def ignore(self, p: Principal, tenant_id: str, entity_id: str, *, reason: str, days: int) -> EntityRecord:
        p.require(Permission.INVENTORY_WRITE, tenant_id)
        if not reason.strip():
            raise ValidationFailed("say why it is ignored")
        days = max(0, min(days, 365))
        async with self.store.tenant_lock(tenant_id):
            e = await self._entity(tenant_id, entity_id)
            e.ignored_until = self.now() + timedelta(days=days) if days else None
            e.ignore_reason = reason.strip()[:500] if days else None
            await self.store.put_entity(e)
            await self.ctx.log(
                "inventory_entity",
                e.id,
                "ignore" if days else "unignore",
                p.actor,
                after={"days": days, "reason": reason},
            )
            await self.pipeline.reconcile_tenant(tenant_id)
        await self._republish()
        return await self._entity(tenant_id, entity_id)

    async def _republish(self) -> None:
        """Findings feed the gateways' risk through the catalog (open_findings, flagged_tools). A new
        catalog version is stored only when that content actually changed."""
        if self.catalog is None:
            return
        try:
            await self.catalog.publish()
        except Exception:  # noqa: BLE001 - the inventory change stands; the next publish catches up
            logger.warning("catalog republish after an inventory change failed", exc_info=True)

    async def reconcile(self, p: Principal, tenant_id: str) -> dict[str, int]:
        p.require(Permission.INVENTORY_WRITE, tenant_id)
        await self._tenant(tenant_id)
        stats = await self.pipeline.reconcile_tenant(tenant_id)
        await self._republish()
        return {
            "findings_opened": stats.findings_opened,
            "findings_resolved": stats.findings_resolved,
            "state_changes": len(stats.state_changes),
        }

    # ---- findings ------------------------------------------------------------------------------

    async def list_findings(
        self, p: Principal, tenant_id: str, *, status: str | None = "open", kind: str | None = None, limit: int = 500
    ) -> list[FindingRecord]:
        p.require(Permission.READ, tenant_id)
        return await self.store.list_findings(tenant_id, status=status, kind=kind, limit=max(1, min(limit, 2000)))

    async def update_finding(
        self, p: Principal, tenant_id: str, finding_id: str, *, status: str, note: str = ""
    ) -> FindingRecord:
        """accepted = known and fine (not reopened); resolved = fixed; open = reopen."""
        p.require(Permission.INVENTORY_WRITE, tenant_id)
        if status not in ("accepted", "resolved", "open"):
            raise ValidationFailed("status must be accepted, resolved or open")
        f = await self.store.get_finding(tenant_id, finding_id)
        if f is None:
            raise NotFound(f"finding {finding_id} not found")
        allowed = {"open": {"accepted", "resolved"}, "accepted": {"open"}, "resolved": {"open"}}
        if status not in allowed.get(f.status, set()):
            raise StateConflict(f"a finding that is {f.status} can't become {status}")
        now = self.now()
        before = f.status
        f.status = status  # type: ignore[assignment]
        f.note = note.strip()[:2000]
        f.updated_at = now
        f.resolved_at, f.resolved_by = (None, None) if status == "open" else (now, p.actor)
        if f.kind == "tool_definition_changed" and status == "accepted":
            e = await self.store.get_entity(tenant_id, f.entity_id)
            if e is not None:  # the new definition is approved: pin it
                e.attrs = {
                    **e.attrs,
                    "pinned": {
                        "definition_hash": f.details.get("new_hash"),
                        "description": f.details.get("new_description", ""),
                        "at": now.isoformat(),
                        "approved_by": p.actor,
                    },
                }
                await self.store.put_entity(e)
        await self.store.put_finding(f)
        await self._republish()
        await self.ctx.log(
            "inventory_finding",
            f.id,
            status,
            p.actor,
            before={"status": before},
            after={"status": status, "note": f.note},
        )
        return f

    async def summary(self, p: Principal, tenant_id: str) -> dict[str, Any]:
        p.require(Permission.READ, tenant_id)
        entities = await self.store.list_entities(tenant_id, limit=1_000_000)
        by_kind: dict[str, int] = {}
        for e in entities:
            by_kind[e.kind] = by_kind.get(e.kind, 0) + 1
        findings = await self.store.list_findings(tenant_id, status="open", limit=1_000_000)
        by_severity = {"high": 0, "medium": 0, "low": 0}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        return {"entities": len(entities), "by_kind": by_kind, "open_findings": by_severity}


def _public(c: ConnectorRecord) -> dict[str, Any]:
    return c.model_dump(mode="json", exclude={"lease_owner", "lease_until"})


async def scheduler_loop(svc: DiscoveryService, tick_seconds: float = 60.0, housekeeping_hours: float = 6.0) -> None:
    """Runs due connectors every tick; prunes evidence and re-reconciles (staleness) periodically."""
    last_housekeeping = 0.0
    loop = asyncio.get_running_loop()
    while True:
        try:
            await svc.run_due()
            if loop.time() - last_housekeeping >= housekeeping_hours * 3600:
                last_housekeeping = loop.time()
                await svc.housekeeping()
        except Exception as exc:  # noqa: BLE001 - the scheduler must keep going
            logger.warning("discovery scheduler tick failed: %s", exc.__class__.__name__)
        await asyncio.sleep(tick_seconds)
