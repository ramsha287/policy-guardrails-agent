"""Discovery pipeline: observations -> entities -> classification -> reconciliation -> findings.

One connector run:

    1. collect     the connector yields observations (capped at max_observations)
    2. resolve     each fact joins the entity that shares a strong key (several -> they are merged),
                   or becomes a new entity; the fact's signals, attributes and volume are stored
                   under the connector (`attrs.by_source[<connector id>]`), replacing what that
                   connector said last time
    3. edges       relations are temporal: unchanged -> last_seen refreshed; changed -> the old row
                   is closed and a new one opened; gone -> closed (snapshot sources, after a clean
                   run) or aged out after 30 days (log sources)
    4. snapshot    after a clean run of a snapshot source, entities it no longer lists lose that
                   source (a deleted deployment stops being a shadow agent)
    5. reconcile   the whole tenant: registry sync, dedupe by strong key, classify, state, findings

A partial run (warnings or an error part-way) never removes anything: a source that answered half
its questions must not make the other half look deleted.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ..domain.inventory import (
    STALE_AFTER_DAYS,
    ConnectorRecord,
    EdgeRecord,
    EntityRecord,
    FindingRecord,
    ObservationRecord,
    SyncRunRecord,
)
from ..domain.records import utcnow
from ..events import EventPublisher
from ..store.base import Store
from . import classify
from .model import CollectContext, ConnectorError, EntityFact, Observation
from .registry import get as get_connector

logger = logging.getLogger(__name__)

INVENTORY_CHANNEL = "guardrail:inventory.changed"
VOLUME_WINDOW = timedelta(days=7)
EDGE_TTL = timedelta(days=STALE_AFTER_DAYS)
DEFAULT_MAX_OBSERVATIONS = 20_000
SYSTEM_ACTOR = "discovery"


def _iso(t: datetime) -> str:
    return t.isoformat()


def _when(v: Any) -> datetime | None:
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v)
        except ValueError:
            return None
    return None


def _clean(value: Any, limit: int = 4000) -> Any:
    """Remote text goes into JSONB/TEXT: drop NUL characters (Postgres rejects them), cap lengths."""
    if isinstance(value, str):
        return value.replace("\x00", "")[:limit]
    if isinstance(value, dict):
        return {str(k).replace("\x00", "")[:200]: _clean(v, limit) for k, v in list(value.items())[:500]}
    if isinstance(value, (list, tuple, set)):
        return [_clean(v, limit) for v in list(value)[:500]]
    return value


def _sanitize_observation(obs: Observation) -> Observation:
    obs.source_ref = _clean(obs.source_ref, 2000)
    obs.attrs = _clean(obs.attrs)
    for f in obs.entities:
        f.name = _clean(f.name, 500) or "?"
        f.owner = _clean(f.owner, 255) if f.owner else None
        f.environment = f.environment if f.environment in ("dev", "staging", "production") else None
        f.strong_keys = [_clean(k, 1000) for k in f.strong_keys if k]
        f.weak_keys = [_clean(k, 1000) for k in f.weak_keys if k]
        f.attrs = _clean(f.attrs)
    for e in obs.edges:
        e.attrs = _clean(e.attrs)
    return obs


def payload_hash(obs: Observation) -> str:
    facts = [(f.kind, sorted(f.strong_keys), sorted(f.signals), f.attrs) for f in obs.entities]
    edges = [(e.src, e.dst, e.kind, e.attrs) for e in obs.edges]
    raw = json.dumps([obs.kind, obs.source_ref, obs.attrs, facts, edges], sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def signals_of(e: EntityRecord) -> set[str]:
    out: set[str] = set()
    for entry in (e.attrs.get("by_source") or {}).values():
        out.update(entry.get("signals") or [])
    return out


def observed_by_connector(e: EntityRecord) -> bool:
    return any(k != classify.REGISTRY_SOURCE for k in (e.attrs.get("by_source") or {}))


def _refresh_derived(e: EntityRecord, now: datetime) -> None:
    """sources, last_seen, environment and volumes follow from attrs.by_source."""
    by_source: dict[str, dict[str, Any]] = e.attrs.get("by_source") or {}
    e.sources = sorted(by_source)
    seen = [t for k, v in by_source.items() if k != classify.REGISTRY_SOURCE and (t := _when(v.get("at")))]
    if seen:
        e.last_seen = max(seen)
    recent = [v for k, v in by_source.items() if (t := _when(v.get("at"))) and t >= now - VOLUME_WINDOW]
    e.managed_volume = sum(int(v.get("managed") or 0) for v in recent)
    e.direct_volume = sum(int(v.get("direct") or 0) for v in recent)
    envs = [v.get("environment") for v in by_source.values() if v.get("environment")]
    if envs and not e.environment:
        e.environment = envs[0]
    owners = [v.get("owner") for v in by_source.values() if v.get("owner")]
    if owners:
        e.owner_guess = owners[0]


@dataclass
class RunStats:
    entities_created: int = 0
    entities_updated: int = 0
    edges_opened: int = 0
    edges_closed: int = 0
    findings_opened: int = 0
    findings_resolved: int = 0
    state_changes: list[tuple[str, str, str]] = field(default_factory=list)  # (entity id, before, after)


class Resolver:
    """Per-run working set: entities touched in this run, indexed by strong key."""

    def __init__(self, store: Store, tenant_id: str) -> None:
        self.store = store
        self.tenant_id = tenant_id
        self.by_id: dict[str, EntityRecord] = {}
        self.by_key: dict[str, str] = {}
        self.created: set[str] = set()
        self.merged_away: dict[str, str] = {}  # old id -> surviving id

    def _index(self, e: EntityRecord) -> None:
        self.by_id[e.id] = e
        for k in e.strong_keys:
            self.by_key[k] = e.id

    async def candidates(self, keys: list[str]) -> list[EntityRecord]:
        found: dict[str, EntityRecord] = {}
        missing = []
        for k in keys:
            if k in self.by_key:
                eid = self.by_key[k]
                found[eid] = self.by_id[eid]
            else:
                missing.append(k)
        if missing:
            for e in await self.store.find_entities(self.tenant_id, missing):
                eid = self.merged_away.get(e.id, e.id)
                if eid not in self.by_id:
                    self._index(e)
                found[eid] = self.by_id[eid]
        return sorted(found.values(), key=lambda e: (e.first_seen, e.id))

    def add(self, e: EntityRecord, created: bool = False) -> None:
        self._index(e)
        if created:
            self.created.add(e.id)


def merge_into(keep: EntityRecord, other: EntityRecord) -> None:
    """Fold `other` into `keep` (both in memory). Callers repoint edges/findings and delete `other`."""
    keep.strong_keys = sorted(set(keep.strong_keys) | set(other.strong_keys))
    keep.weak_keys = sorted(set(keep.weak_keys) | set(other.weak_keys))
    by_source = dict(keep.attrs.get("by_source") or {})
    for src, entry in (other.attrs.get("by_source") or {}).items():
        mine = by_source.get(src)
        if mine is None or (_when(entry.get("at")) or keep.first_seen) > (_when(mine.get("at")) or keep.first_seen):
            by_source[src] = entry
    keep.attrs = {**other.attrs, **keep.attrs, "by_source": by_source}
    merged = set(keep.attrs.get("merged_from") or []) | set(other.attrs.get("merged_from") or []) | {other.id}
    keep.attrs["merged_from"] = sorted(merged)
    keep.first_seen = min(keep.first_seen, other.first_seen)
    keep.last_seen = max(keep.last_seen, other.last_seen)
    if keep.kind != "agent" and other.kind == "agent" and keep.kind not in ("workload", "endpoint", "identity"):
        keep.kind = "agent"
    keep.registry_agent_id = keep.registry_agent_id or other.registry_agent_id
    if other.ignored_until and (keep.ignored_until is None or other.ignored_until > keep.ignored_until):
        keep.ignored_until, keep.ignore_reason = other.ignored_until, other.ignore_reason


class DiscoveryPipeline:
    def __init__(
        self,
        store: Store,
        events: EventPublisher,
        *,
        clock: Callable[[], datetime] = utcnow,
        max_observations: int = DEFAULT_MAX_OBSERVATIONS,
    ) -> None:
        self.store = store
        self.events = events
        self.now = clock
        self.max_observations = max_observations

    # ---- one connector run -----------------------------------------------------------------------

    async def run(self, connector: ConnectorRecord, ctx: CollectContext, run: SyncRunRecord) -> SyncRunRecord:
        impl = get_connector(connector.kind)
        if impl is None:
            run.status, run.error = "error", f"unknown connector kind {connector.kind}"
            return run
        now = ctx.now
        stats = RunStats()
        collected: list[Observation] = []
        error: str | None = None
        truncated = False

        # 1. collect (network, no store writes, no lock)
        try:
            config = impl.Config.model_validate(connector.config)
            async for obs in impl.collect(config, ctx):
                if len(collected) >= self.max_observations:
                    truncated = True
                    ctx.warn(f"stopped at {self.max_observations} observations (DISCOVERY_MAX_OBSERVATIONS)")
                    break
                collected.append(_sanitize_observation(obs))
        except ConnectorError as exc:
            error = str(exc)
        except Exception as exc:  # noqa: BLE001 - a connector bug is a failed run, not a crashed scheduler
            logger.warning("connector %s failed: %s", connector.id, exc.__class__.__name__, exc_info=exc)
            error = f"{exc.__class__.__name__}: {str(exc)[:300]}"
        clean = error is None and not ctx.warnings and not truncated

        # 2. apply, one tenant at a time: runs read-modify-write entities and reconcile the tenant,
        #    so two connectors of one tenant (or two replicas) must not interleave here
        async with self.store.tenant_lock(connector.tenant_id):
            resolver = Resolver(self.store, connector.tenant_id)
            edges_seen: dict[tuple[str, str, str], tuple[dict[str, Any], float, str]] = {}
            observations = [
                await self._apply(obs, connector, run, resolver, edges_seen, now, stats) for obs in collected
            ]
            await self.store.add_observations(observations)
            for e in resolver.by_id.values():
                _refresh_derived(e, now)
                await self.store.put_entity(e)
            stats.entities_created = len(resolver.created)
            stats.entities_updated = len(resolver.by_id) - len(resolver.created)
            await self._reconcile_edges(
                connector, edges_seen, now, stats, full=clean and impl.full_snapshot, resolver=resolver
            )
            if clean and impl.full_snapshot:
                await self._drop_unseen(connector, resolver, now)
            await self.reconcile_tenant(connector.tenant_id, stats=stats, now=now)

        run.observations = len(observations)
        run.entities_created, run.entities_updated = stats.entities_created, stats.entities_updated
        run.edges_opened, run.edges_closed = stats.edges_opened, stats.edges_closed
        run.findings_opened, run.findings_resolved = stats.findings_opened, stats.findings_resolved
        run.warnings = list(ctx.warnings)
        run.error = error
        run.status = "error" if error and not observations else ("partial" if not clean else "ok")
        run.finished_at = self.now()
        return run

    async def _apply(
        self,
        obs: Observation,
        connector: ConnectorRecord,
        run: SyncRunRecord,
        resolver: Resolver,
        edges_seen: dict[tuple[str, str, str], tuple[dict[str, Any], float, str]],
        now: datetime,
        stats: RunStats,
    ) -> ObservationRecord:
        record = ObservationRecord(
            tenant_id=connector.tenant_id,
            connector_id=connector.id,
            run_id=run.id,
            kind=obs.kind,
            source_ref=obs.source_ref[:2000],
            observed_at=obs.observed_at or now,
            payload_hash=payload_hash(obs),
            attrs=obs.attrs,
        )
        refs: dict[str, str] = {}
        for fact in obs.entities:
            entity = await self._resolve(fact, connector, run.id, resolver, now, stats)
            refs[fact.ref] = entity.id
        record.entity_id = refs.get("self") or (next(iter(refs.values()), None))
        for edge in obs.edges:
            src, dst = refs.get(edge.src), refs.get(edge.dst)
            if src and dst and src != dst:
                edges_seen[(src, dst, edge.kind)] = (edge.attrs, edge.confidence, record.id)
        return record

    async def _resolve(
        self,
        fact: EntityFact,
        connector: ConnectorRecord,
        run_id: str,
        resolver: Resolver,
        now: datetime,
        stats: RunStats,
    ) -> EntityRecord:
        keys = sorted(set(fact.strong_keys))
        found = await resolver.candidates(keys)
        if not found:
            entity = EntityRecord(
                tenant_id=connector.tenant_id,
                kind=fact.kind,
                name=fact.name[:500],
                strong_keys=keys,
                first_seen=now,
                last_seen=now,
                environment=fact.environment or connector.environment,
            )
            resolver.add(entity, created=True)
        else:
            entity = found[0]
            for other in found[1:]:
                await self._merge(entity, other, resolver, now)
        entity.strong_keys = sorted(set(entity.strong_keys) | set(keys))
        entity.weak_keys = sorted(set(entity.weak_keys) | set(fact.weak_keys))
        if fact.kind == "agent" and entity.kind in ("tool", "datastore", "destination", "project", "credential"):
            entity.kind = "agent"
        if not entity.environment:
            entity.environment = fact.environment or connector.environment
        by_source = dict(entity.attrs.get("by_source") or {})
        prev = by_source.get(connector.id)
        entry = {
            "kind": connector.kind,
            "connector": connector.name,
            "signals": sorted(fact.signals),
            "attrs": fact.attrs,
            "managed": fact.managed_volume,
            "direct": fact.direct_volume,
            "at": _iso(now),
            "run": run_id,
            "environment": fact.environment or connector.environment,
            "owner": fact.owner,
        }
        if prev is not None and prev.get("run") == run_id:  # same entity reported twice in one run: add up
            entry["signals"] = sorted(set(prev.get("signals") or []) | fact.signals)
            entry["attrs"] = {**(prev.get("attrs") or {}), **fact.attrs}
            entry["managed"] = int(prev.get("managed") or 0) + fact.managed_volume
            entry["direct"] = int(prev.get("direct") or 0) + fact.direct_volume
        by_source[connector.id] = entry
        entity.attrs = {**entity.attrs, "by_source": by_source}
        entity.updated_at = now
        await self._check_definition(entity, fact, now, stats)
        resolver.add(entity)
        return entity

    async def _check_definition(self, entity: EntityRecord, fact: EntityFact, now: datetime, stats: RunStats) -> None:
        """Pin MCP tool definitions; a changed definition opens a finding (rug-pull detection)."""
        new_hash = fact.attrs.get("definition_hash")
        if entity.kind != "tool" or not new_hash:
            return
        pinned = entity.attrs.get("pinned") or {}
        if not pinned:
            entity.attrs["pinned"] = {
                "definition_hash": new_hash,
                "description": fact.attrs.get("description", ""),
                "at": _iso(now),
            }
            return
        open_findings = await self.store.list_findings(
            entity.tenant_id, entity_id=entity.id, kind="tool_definition_changed", status="open"
        )
        if new_hash == pinned.get("definition_hash"):
            for f in open_findings:  # reverted to the approved definition
                await self._resolve_finding(f, now, "the definition is back to the pinned version", stats)
            return
        if any(f.details.get("new_hash") == new_hash for f in open_findings):
            return
        for f in open_findings:  # superseded by a newer change
            await self._resolve_finding(f, now, "superseded by a newer change", stats)
        finding = FindingRecord(
            tenant_id=entity.tenant_id,
            entity_id=entity.id,
            kind="tool_definition_changed",
            severity="high",
            summary=f"Tool definition changed: {entity.name}",
            details={
                "old_hash": pinned.get("definition_hash"),
                "new_hash": new_hash,
                "old_description": pinned.get("description", ""),
                "new_description": fact.attrs.get("description", ""),
            },
            created_at=now,
            updated_at=now,
        )
        await self.store.put_finding(finding)
        stats.findings_opened += 1
        await self._event(
            entity.tenant_id, "finding.opened", entity.id, {"finding_id": finding.id, "kind": finding.kind}
        )

    async def _merge(self, keep: EntityRecord, other: EntityRecord, resolver: Resolver | None, now: datetime) -> None:
        merge_into(keep, other)
        # Current relations of `keep`, so re-pointed ones that already exist are not duplicated.
        current = {
            (e.src, e.dst, e.kind, e.source)
            for e in await self.store.list_edges(keep.tenant_id, entity_ids=[keep.id])
            if e.valid_to is None
        }
        for edge in await self.store.list_edges(keep.tenant_id, entity_ids=[other.id]):
            was_current = edge.valid_to is None
            if was_current:
                edge.valid_to = now
                await self.store.put_edge(edge)
            src = keep.id if edge.src == other.id else edge.src
            dst = keep.id if edge.dst == other.id else edge.dst
            ident = (src, dst, edge.kind, edge.source)
            if was_current and src != dst and ident not in current:
                current.add(ident)
                await self.store.put_edge(
                    edge.model_copy(
                        update={"id": str(uuid.uuid4()), "src": src, "dst": dst, "valid_from": now, "valid_to": None}
                    )
                )
        # One finding per (entity, kind): `keep`'s own wins; the other's duplicate is resolved.
        have = {
            (f.kind, f.status)
            for f in await self.store.list_findings(keep.tenant_id, entity_id=keep.id)
            if f.status in ("open", "accepted")
        }
        for f in await self.store.list_findings(keep.tenant_id, entity_id=other.id):
            moved = f.model_copy(update={"entity_id": keep.id, "updated_at": now})
            if f.status in ("open", "accepted") and any(k == f.kind for k, _ in have):
                moved.status, moved.resolved_at, moved.resolved_by = "resolved", now, SYSTEM_ACTOR
                moved.note = "duplicate: merged into another entity's finding"
            elif f.status in ("open", "accepted"):
                have.add((f.kind, f.status))
            await self.store.put_finding(moved)
        await self.store.delete_entity(keep.tenant_id, other.id)
        if resolver is not None:
            resolver.by_id.pop(other.id, None)
            resolver.created.discard(other.id)
            resolver.merged_away[other.id] = keep.id
            for k, v in list(resolver.by_key.items()):
                if v == other.id:
                    resolver.by_key[k] = keep.id
            resolver.add(keep)
        else:
            await self.store.put_entity(keep)

    async def _reconcile_edges(
        self,
        connector: ConnectorRecord,
        seen: dict[tuple[str, str, str], tuple[dict[str, Any], float, str]],
        now: datetime,
        stats: RunStats,
        *,
        full: bool,
        resolver: Resolver,
    ) -> None:
        existing: dict[tuple[str, str, str], EdgeRecord] = {}
        for e in await self.store.list_edges(connector.tenant_id, source=connector.id):
            src = resolver.merged_away.get(e.src, e.src)
            dst = resolver.merged_away.get(e.dst, e.dst)
            existing[(src, dst, e.kind)] = e
        for key, (attrs, confidence, evidence) in seen.items():
            current = existing.pop(key, None)
            if current is not None and current.attrs == attrs and current.confidence == confidence:
                current.last_seen = now
                current.evidence_ref = evidence
                await self.store.put_edge(current)
                continue
            if current is not None:  # changed: close the old version
                current.valid_to = now
                await self.store.put_edge(current)
                stats.edges_closed += 1
            src, dst, kind = key
            await self.store.put_edge(
                EdgeRecord(
                    tenant_id=connector.tenant_id,
                    src=src,
                    dst=dst,
                    kind=kind,
                    attrs=attrs,
                    source=connector.id,
                    confidence=confidence,
                    valid_from=now,
                    last_seen=now,
                    evidence_ref=evidence,
                )
            )
            stats.edges_opened += 1
        for e in existing.values():  # not reported this run
            if full or e.last_seen < now - EDGE_TTL:
                e.valid_to = now
                await self.store.put_edge(e)
                stats.edges_closed += 1

    async def _drop_unseen(self, connector: ConnectorRecord, resolver: Resolver, now: datetime) -> None:
        """After a clean snapshot run: entities this connector no longer lists lose it as a source."""
        for e in await self.store.list_entities(connector.tenant_id, limit=1_000_000):
            if e.id in resolver.by_id:
                continue
            by_source = dict(e.attrs.get("by_source") or {})
            if connector.id not in by_source:
                continue
            gone = by_source.pop(connector.id)
            history = list(e.attrs.get("removed_from") or [])[-9:]
            history.append({"connector": connector.id, "kind": gone.get("kind"), "at": _iso(now)})
            e.attrs = {**e.attrs, "by_source": by_source, "removed_from": history}
            e.updated_at = now
            _refresh_derived(e, now)
            await self.store.put_entity(e)

    # ---- the whole tenant ------------------------------------------------------------------------

    async def reconcile_tenant(
        self, tenant_id: str, *, stats: RunStats | None = None, now: datetime | None = None
    ) -> RunStats:
        """Registry sync, dedupe, classification, state and findings for every entity of a tenant.
        Holds the tenant lock (re-entrant), so it never interleaves with a run or another reconcile."""
        async with self.store.tenant_lock(tenant_id):
            return await self._reconcile_tenant(tenant_id, stats=stats, now=now)

    async def _reconcile_tenant(self, tenant_id: str, *, stats: RunStats | None, now: datetime | None) -> RunStats:
        stats = stats or RunStats()
        now = now or self.now()
        await self._sync_registry(tenant_id, now)
        entities = await self.store.list_entities(tenant_id, limit=1_000_000)
        entities = await self._dedupe(entities, now)
        registered = {a.agent_id: a for a in await self.store.list_agents(tenant_id)}
        open_by_entity: dict[str, list[FindingRecord]] = {}
        for f in await self.store.list_findings(tenant_id, status="open", limit=1_000_000):
            open_by_entity.setdefault(f.entity_id, []).append(f)
        accepted = {
            (f.entity_id, f.kind) for f in await self.store.list_findings(tenant_id, status="accepted", limit=1_000_000)
        }
        weak_index: dict[str, set[str]] = {}
        for e in entities:
            for k in e.weak_keys:
                weak_index.setdefault(k, set()).add(e.id)

        for e in entities:
            before = (
                e.state, e.agent_likelihood, e.registry_agent_id, tuple(e.reasons), tuple(e.sources), e.last_seen,
                tuple(e.probable_matches), e.managed_volume, e.direct_volume, e.owner_guess, e.environment,
            )  # fmt: skip
            e.probable_matches = sorted({i for k in e.weak_keys for i in weak_index.get(k, ()) if i != e.id})[:50]
            by_source = dict(e.attrs.get("by_source") or {})
            # log-style sources age out: what nobody has reported for 30 days is no longer evidence
            for src, entry in list(by_source.items()):
                at = _when(entry.get("at"))
                if src != classify.REGISTRY_SOURCE and at is not None and at < now - EDGE_TTL:
                    by_source.pop(src)
            e.attrs = {**e.attrs, "by_source": by_source}
            _refresh_derived(e, now)

            e.registry_agent_id = self._registry_link(e, registered)
            signals = signals_of(e)
            likelihood, why = classify.classify(e.kind, signals)
            e.agent_likelihood = likelihood  # type: ignore[assignment]
            observed = observed_by_connector(e)
            state, reasons = classify.state_of(e, signals, observed, now)
            e.state = state  # type: ignore[assignment]
            ignored = [f"ignored until {e.ignored_until.date().isoformat()}: {e.ignore_reason}"] if (
                e.ignored_until is not None and e.ignored(now)
            ) else []  # fmt: skip
            e.reasons = why + reasons + ignored
            if e.registry_agent_id and registered.get(e.registry_agent_id) and registered[e.registry_agent_id].owner:
                e.owner_guess = registered[e.registry_agent_id].owner

            after = (
                e.state, e.agent_likelihood, e.registry_agent_id, tuple(e.reasons), tuple(e.sources), e.last_seen,
                tuple(e.probable_matches), e.managed_volume, e.direct_volume, e.owner_guess, e.environment,
            )  # fmt: skip
            if after != before:
                e.updated_at = now
                await self.store.put_entity(e)
                if before[0] != e.state:
                    stats.state_changes.append((e.id, before[0], e.state))
                    await self._event(
                        tenant_id, "entity.state_changed", e.id, {"from": before[0], "to": e.state, "name": e.name}
                    )

            wanted = classify.wanted_findings(e, observed, now)
            for f in open_by_entity.get(e.id, []):
                if f.kind in classify.AUTO_FINDINGS and f.kind not in wanted:
                    await self._resolve_finding(f, now, "no longer applies", stats)
                elif f.kind == "tool_definition_changed" and not observed:
                    await self._resolve_finding(f, now, "the tool is no longer listed by any server", stats)
            have = {f.kind for f in open_by_entity.get(e.id, [])}
            for kind, (severity, summary) in wanted.items():
                if kind in have or (e.id, kind) in accepted:
                    continue
                finding = FindingRecord(
                    tenant_id=tenant_id,
                    entity_id=e.id,
                    kind=kind,  # type: ignore[arg-type]
                    severity=severity,  # type: ignore[arg-type]
                    summary=summary,
                    details={"reasons": e.reasons, "sources": e.sources, "owner_guess": e.owner_guess},
                    created_at=now,
                    updated_at=now,
                )
                await self.store.put_finding(finding)
                stats.findings_opened += 1
                await self._event(
                    tenant_id, "finding.opened", e.id, {"finding_id": finding.id, "kind": kind, "severity": severity}
                )
        return stats

    @staticmethod
    def _registry_link(e: EntityRecord, registered: dict[str, Any]) -> str | None:
        for prefix in ("agent:", "agent-name:"):
            for k in e.strong_keys:
                if k.startswith(prefix) and k[len(prefix) :] in registered:
                    return k[len(prefix) :]
        return None

    async def _sync_registry(self, tenant_id: str, now: datetime) -> None:
        """Every registered agent has an entity (so stale and never-seen agents show up)."""
        agents = await self.store.list_agents(tenant_id)
        ids = {a.agent_id for a in agents}
        for a in agents:
            keys = [f"agent:{a.agent_id}", f"agent-name:{a.agent_id}"]
            found = await self.store.find_entities(tenant_id, keys)
            entry = {
                "kind": "registry",
                "connector": "registry",
                "signals": ["registered"],
                "attrs": {"base_trust_score": a.base_trust_score, "allowed_tools": a.allowed_tools},
                "managed": 0,
                "direct": 0,
                "owner": a.owner,
            }
            if not found:
                e = EntityRecord(
                    tenant_id=tenant_id,
                    kind="agent",
                    name=a.agent_id,
                    strong_keys=keys,
                    first_seen=now,
                    last_seen=now,
                    attrs={"by_source": {classify.REGISTRY_SOURCE: entry}},
                    registry_agent_id=a.agent_id,
                )
                await self.store.put_entity(e)
                continue
            e = found[0]
            by_source = dict(e.attrs.get("by_source") or {})
            if by_source.get(classify.REGISTRY_SOURCE) != entry or not set(keys) <= set(e.strong_keys):
                by_source[classify.REGISTRY_SOURCE] = entry
                e.attrs = {**e.attrs, "by_source": by_source}
                e.strong_keys = sorted(set(e.strong_keys) | set(keys))
                await self.store.put_entity(e)
        # agents removed from the registry stop being "registered"
        for e in await self.store.list_entities(tenant_id, limit=1_000_000):
            by_source = e.attrs.get("by_source") or {}
            if (
                classify.REGISTRY_SOURCE in by_source
                and e.registry_agent_id not in ids
                and not any(
                    k[len(p) :] in ids for k in e.strong_keys for p in ("agent:", "agent-name:") if k.startswith(p)
                )
            ):
                rest = {k: v for k, v in by_source.items() if k != classify.REGISTRY_SOURCE}
                e.attrs = {**e.attrs, "by_source": rest}
                e.registry_agent_id = None
                await self.store.put_entity(e)

    async def _dedupe(self, entities: list[EntityRecord], now: datetime) -> list[EntityRecord]:
        """Entities sharing a strong key are one thing (e.g. created by two concurrent runs): merge."""
        owner: dict[str, EntityRecord] = {}
        gone: set[str] = set()
        for e in sorted(entities, key=lambda x: (x.first_seen, x.id)):
            if e.id in gone:
                continue
            target = next((owner[k] for k in e.strong_keys if k in owner and owner[k].id != e.id), None)
            if target is None:
                for k in e.strong_keys:
                    owner[k] = e
                continue
            await self._merge(target, e, None, now)
            gone.add(e.id)
            for k in target.strong_keys:
                owner[k] = target
        return [e for e in entities if e.id not in gone]

    async def _resolve_finding(self, f: FindingRecord, now: datetime, note: str, stats: RunStats) -> None:
        f.status, f.resolved_at, f.resolved_by, f.updated_at = "resolved", now, SYSTEM_ACTOR, now
        f.note = note
        await self.store.put_finding(f)
        stats.findings_resolved += 1

    async def _event(self, tenant_id: str, kind: str, entity_id: str, data: dict[str, Any]) -> None:
        try:
            await self.events.publish(
                INVENTORY_CHANNEL,
                {"type": f"inventory.{kind}.v1", "tenant_id": tenant_id, "entity_id": entity_id, **data},
            )
        except Exception:  # noqa: BLE001 - events are notifications; the store is the record
            logger.warning("could not publish inventory event")
