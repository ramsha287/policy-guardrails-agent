"""Prometheus metrics for the control plane (GET /metrics).

Counters move with events; gauges are recomputed from the store every METRICS_REFRESH_SECONDS
by a background task, so a scrape never queries the database.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from prometheus_client import Counter, Gauge

from .domain.records import ENVIRONMENTS, utcnow

if TYPE_CHECKING:
    from .services.context import Ctx

logger = logging.getLogger(__name__)

SNAPSHOTS_PUBLISHED = Counter("cp_snapshots_published_total", "Snapshots published", ["environment", "kind"])
REVIEW_DECISIONS = Counter("cp_review_decisions_total", "Human review decisions", ["decision"])
REVIEWS_PENDING = Gauge("cp_reviews_pending", "Held requests waiting for a reviewer")
REVIEWS_OLDEST_PENDING_SECONDS = Gauge("cp_reviews_oldest_pending_seconds", "Age of the oldest pending review")
REVIEWS_EXPIRED_UNDECIDED = Gauge("cp_reviews_expired_undecided", "Recent reviews that expired without a decision")
PUBLISH_REQUESTS_PENDING = Gauge("cp_publish_requests_pending", "Publish/rollback requests waiting for approval")
GATEWAYS = Gauge("cp_gateways", "Gateways by heartbeat state", ["environment", "state"])
DISCOVERY_RUNS = Counter("cp_discovery_runs_total", "Discovery connector runs", ["kind", "status"])
INVENTORY_AGENTS = Gauge("cp_inventory_agents", "Discovered agents by reconciliation state", ["state"])
INVENTORY_FINDINGS_OPEN = Gauge("cp_inventory_findings_open", "Open discovery findings", ["severity"])
DISCOVERY_CONNECTORS_FAILING = Gauge("cp_discovery_connectors_failing", "Connectors whose last run failed")
GATEWAYS_BEHIND = Gauge("cp_gateways_behind", "Live gateways not serving the current snapshot", ["environment"])


async def refresh_gauges(ctx: Ctx) -> None:
    store = ctx.store
    now = utcnow()
    reviews = await store.list_reviews(None, "pending", limit=1000)
    pending = [r for r in reviews if r.effective_status(now) == "pending"]
    REVIEWS_PENDING.set(len(pending))
    REVIEWS_EXPIRED_UNDECIDED.set(len(reviews) - len(pending))
    REVIEWS_OLDEST_PENDING_SECONDS.set(max(((now - r.created_at).total_seconds() for r in pending), default=0))
    requests = await store.list_publish_requests(None, "pending")
    PUBLISH_REQUESTS_PENDING.set(len(requests))
    stale_after = ctx.policy.gateway_stale_seconds
    for env in ENVIRONMENTS:
        gateways = await store.list_gateways(env)
        live = [g for g in gateways if (now - g.last_seen).total_seconds() <= stale_after]
        GATEWAYS.labels(env, "live").set(len(live))
        GATEWAYS.labels(env, "stale").set(len(gateways) - len(live))
        current = await store.current_snapshot(env)
        behind = [g for g in live if current is not None and g.snapshot_version != current.version]
        GATEWAYS_BEHIND.labels(env).set(len(behind))
    await refresh_inventory_gauges(ctx)


async def refresh_inventory_gauges(ctx: Ctx) -> None:
    from .domain.inventory import ENTITY_STATES

    store = ctx.store
    states = {s: 0 for s in ENTITY_STATES if s != "not_agent"}
    severities = {"high": 0, "medium": 0, "low": 0}
    for t in await store.list_tenants():
        for e in await store.list_entities(t.id, agents_only=True, limit=1_000_000):
            if e.state in states:
                states[e.state] += 1
        for f in await store.list_findings(t.id, status="open", limit=1_000_000):
            severities[f.severity] = severities.get(f.severity, 0) + 1
    for s, n in states.items():
        INVENTORY_AGENTS.labels(s).set(n)
    for s, n in severities.items():
        INVENTORY_FINDINGS_OPEN.labels(s).set(n)
    connectors = await store.list_connectors()
    DISCOVERY_CONNECTORS_FAILING.set(sum(1 for c in connectors if c.enabled and c.last_status == "error"))


async def refresh_loop(ctx: Ctx, interval_seconds: float = 30.0) -> None:
    while True:
        try:
            await refresh_gauges(ctx)
        except Exception as exc:  # noqa: BLE001 - metrics must never take the service down
            logger.warning("metrics refresh failed: %s", exc.__class__.__name__)
        await asyncio.sleep(interval_seconds)
