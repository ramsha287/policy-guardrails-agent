"""Our own enforcement points: which agents call through the guardrail gateway, and what they touch.

Reads the gateway's audit log (AUDIT_DSN, read-only) for the tenant over a look-back window and
reports, per agent: request volume (the "managed" side of coverage), the tools it calls, the data
stores it reads or writes and the external hosts it sends to (from the action descriptors, which
hold names, never values).

This is what makes an agent "managed": registered AND seen here AND no bypass seen elsewhere.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any, ClassVar

from pydantic import Field

from ..model import CollectContext, ConnectorConfig, ConnectorError, EdgeFact, EntityFact, Observation

ACTIVITY_SQL = """
SELECT e.environment, e.agent_id, e.stage, e.action, e.assurance,
       e.descriptor->>'kind' AS d_kind, e.descriptor->>'verb' AS d_verb, e.descriptor->>'target' AS d_target,
       e.descriptor->>'destination' AS d_destination, e.descriptor->>'destination_host' AS d_host,
       count(*) AS requests, sum(CASE WHEN e.decision = 'block' THEN 1 ELSE 0 END) AS blocked,
       min(e.created_at) AS first_seen, max(e.created_at) AS last_seen
  FROM audit.audit_events e
 WHERE e.tenant_id = :tenant_id AND e.created_at > :since {env}
 GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
 ORDER BY 2, 11 DESC
 LIMIT :max_rows
"""

MODEL_STAGES = ("input", "output")
WRITE_VERBS = ("write", "delete", "admin", "execute")


class GatewayConfig(ConnectorConfig):
    lookback_hours: int = Field(default=24, ge=1, le=24 * 30)
    environment: str | None = Field(default=None, pattern="^(dev|staging|production)$")
    max_rows: int = Field(default=20_000, ge=100, le=200_000)


class GatewayConnector:
    kind: ClassVar[str] = "gateway"
    title: ClassVar[str] = "Guardrail gateway (audit log)"
    description: ClassVar[str] = (
        "Agents calling through the guardrail gateway, with the tools, data stores and hosts they use. "
        "Needs AUDIT_DSN on the control plane."
    )
    full_snapshot: ClassVar[bool] = False
    Config: ClassVar[type[ConnectorConfig]] = GatewayConfig

    async def collect(self, config: GatewayConfig, ctx: CollectContext) -> AsyncIterator[Observation]:
        if ctx.audit_fetch is None:
            raise ConnectorError("the gateway connector needs AUDIT_DSN (read access to the gateway's audit schema)")
        params: dict[str, Any] = {
            "tenant_id": ctx.tenant_id,
            "since": ctx.now - timedelta(hours=config.lookback_hours),
            "max_rows": config.max_rows,
        }
        env = ""
        if config.environment:
            env = "AND e.environment = :environment"
            params["environment"] = config.environment
        rows = await ctx.audit_fetch(ACTIVITY_SQL.format(env=env), params)
        if len(rows) >= config.max_rows:
            ctx.warn(f"activity truncated at {config.max_rows} rows; raise max_rows or shorten lookback_hours")

        by_agent: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for r in rows:
            by_agent.setdefault((str(r["agent_id"]), str(r["environment"])), []).append(r)

        for (agent_id, environment), items in sorted(by_agent.items()):
            yield _agent_observation(agent_id, environment, items, config.lookback_hours)


def _agent_observation(agent_id: str, environment: str, rows: list[dict[str, Any]], hours: int) -> Observation:
    requests = sum(int(r["requests"]) for r in rows)
    signals = {"gateway_client"}
    if any(r["stage"] in MODEL_STAGES for r in rows):
        signals.add("calls_model")
    if any(r["stage"] == "tool" for r in rows):
        signals.add("uses_tools")
    assurances = sorted({str(r["assurance"]) for r in rows if r.get("assurance")})
    agent = EntityFact(
        ref="self",
        kind="agent",
        name=agent_id,
        strong_keys=[f"agent:{agent_id}"],
        signals=signals,
        environment=environment,
        managed_volume=requests,
        attrs={
            "requests": requests,
            "blocked": sum(int(r["blocked"] or 0) for r in rows),
            "assurance": assurances,
            "window_hours": hours,
        },
    )
    facts = [agent]
    edges: list[EdgeFact] = []
    seen: set[str] = set()

    def add(ref: str, fact: EntityFact, kind: str, attrs: dict[str, Any]) -> None:
        if ref not in seen:
            seen.add(ref)
            facts.append(fact)
        edges.append(EdgeFact("self", ref, kind, attrs))

    tool_requests: dict[str, int] = {}
    for r in rows:
        n = int(r["requests"])
        if r["stage"] == "tool":
            tool_requests[r["action"]] = tool_requests.get(r["action"], 0) + n
        target, kind = r.get("d_target"), r.get("d_kind")
        if target and kind in ("sql", "file"):
            verb = "writes_to" if r.get("d_verb") in WRITE_VERBS else "reads_from"
            ref = f"ds:{target}"
            add(ref, EntityFact(ref, "datastore", target, [f"datastore:{target}"], attrs={"kind": kind}), verb, {})
        host = r.get("d_host")
        if host and r.get("d_destination") == "external":
            ref = f"host:{host}"
            add(ref, EntityFact(ref, "destination", host, [f"host:{host}"]), "sends_to", {})
    for action, n in sorted(tool_requests.items()):
        ref = f"tool:{action}"
        add(ref, EntityFact(ref, "tool", action, [f"tool:{action}"]), "uses_tool", {})
        # request counts change every run; keep them on the entity, not the edge (edges version on attrs)
        agent.attrs.setdefault("tool_requests", {})[action] = n

    return Observation(
        kind="gateway.agent_activity",
        source_ref=f"audit.audit_events agent_id={agent_id} environment={environment}",
        entities=facts,
        edges=edges,
        attrs={"agent_id": agent_id, "environment": environment, "requests": requests, "window_hours": hours},
    )
