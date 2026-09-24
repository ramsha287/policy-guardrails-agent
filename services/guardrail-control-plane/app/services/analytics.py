"""Decision analytics over the gateway's audit log (`audit.audit_events`), read through `AUDIT_DSN`.

Three views over the same window:
- `totals`: requests per stage and decision, request latency (avg, p95) and OPA denials. This
  counts every audited request, including ones OPA denied before any guardrail ran.
- `guardrails`: per guardrail version, stage, decision and mode: count, latency and errors.
- `timeseries`: requests per decision per hour (per day for windows over 72 hours).

Filters are optional. A tenant key only ever sees its own tenant.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

from ..domain.rbac import Permission, Principal
from ..domain.records import utcnow

Fetch = Callable[[str, dict[str, Any]], Awaitable[list[dict[str, Any]]]]

MAX_HOURS = 24 * 90

TOTALS_SQL = """
SELECT e.stage, e.decision, count(*) AS requests,
       avg(e.latency_ms) AS avg_latency_ms,
       percentile_cont(0.95) WITHIN GROUP (ORDER BY e.latency_ms) AS p95_latency_ms,
       sum(CASE WHEN e.policy_allow THEN 0 ELSE 1 END) AS policy_denied
  FROM audit.audit_events e
 WHERE {where}
 GROUP BY e.stage, e.decision
 ORDER BY e.stage, e.decision
"""

GUARDRAILS_SQL = """
SELECT r->>'guardrail_id' AS guardrail_id, r->>'version' AS version, e.stage,
       r->>'decision' AS decision, r->>'mode' AS mode, count(*) AS n,
       avg((r->>'latency_ms')::float) AS avg_latency_ms,
       percentile_cont(0.95) WITHIN GROUP (ORDER BY (r->>'latency_ms')::float) AS p95_latency_ms,
       sum(CASE WHEN r->>'error' IS NOT NULL THEN 1 ELSE 0 END) AS errors
  FROM audit.audit_events e
 CROSS JOIN LATERAL jsonb_array_elements(e.guardrail_results) AS r
 WHERE {where}
 GROUP BY 1, 2, 3, 4, 5
 ORDER BY 1, 3, 4
"""

TIMESERIES_SQL = """
SELECT date_trunc('{bucket}', e.created_at) AS bucket, e.decision, count(*) AS requests
  FROM audit.audit_events e
 WHERE {where}
 GROUP BY 1, 2
 ORDER BY 1, 2
"""


def build_filter(environment: str | None, tenant_id: str | None) -> str:
    """WHERE clause with only the filters that are set (keeps parameter types unambiguous)."""
    clauses = ["e.created_at > :since"]
    if environment is not None:
        clauses.append("e.environment = :environment")
    if tenant_id is not None:
        clauses.append("e.tenant_id = :tenant_id")
    return " AND ".join(clauses)


def _num(v: Any, digits: int = 2) -> float | None:
    return None if v is None else round(float(v), digits)


class AnalyticsUnavailable(Exception):
    pass


class AnalyticsService:
    def __init__(self, fetch: Fetch | None) -> None:
        self.fetch = fetch

    async def guardrails(
        self, p: Principal, *, environment: str | None = None, tenant_id: str | None = None, hours: int = 24
    ) -> dict[str, Any]:
        if tenant_id is None and not p.is_platform:
            tenant_id = p.tenant_id
        p.require(Permission.READ, tenant_id)
        if self.fetch is None:
            raise AnalyticsUnavailable("analytics needs AUDIT_DSN (read access to the gateway's audit schema)")
        hours = max(1, min(hours, MAX_HOURS))
        where = build_filter(environment, tenant_id)
        params: dict[str, Any] = {"since": utcnow() - timedelta(hours=hours)}
        if environment is not None:
            params["environment"] = environment
        if tenant_id is not None:
            params["tenant_id"] = tenant_id
        bucket = "hour" if hours <= 72 else "day"

        totals = await self.fetch(TOTALS_SQL.format(where=where), params)
        guardrails = await self.fetch(GUARDRAILS_SQL.format(where=where), params)
        series = await self.fetch(TIMESERIES_SQL.format(where=where, bucket=bucket), params)

        requests = sum(int(r["requests"]) for r in totals)
        by_decision: dict[str, int] = {}
        for r in totals:
            by_decision[r["decision"]] = by_decision.get(r["decision"], 0) + int(r["requests"])
        return {
            "environment": environment,
            "tenant_id": tenant_id,
            "hours": hours,
            "bucket": bucket,
            "summary": {
                "requests": requests,
                "by_decision": by_decision,
                "policy_denied": sum(int(r["policy_denied"] or 0) for r in totals),
                "block_rate": round(by_decision.get("block", 0) / requests, 4) if requests else 0.0,
            },
            "totals": [
                {
                    "stage": r["stage"],
                    "decision": r["decision"],
                    "requests": int(r["requests"]),
                    "avg_latency_ms": _num(r["avg_latency_ms"]),
                    "p95_latency_ms": _num(r["p95_latency_ms"]),
                    "policy_denied": int(r["policy_denied"] or 0),
                }
                for r in totals
            ],
            # kept as `rows` for API compatibility with phase 4 clients
            "rows": [
                {
                    "guardrail_id": r["guardrail_id"],
                    "version": r["version"],
                    "stage": r["stage"],
                    "decision": r["decision"],
                    "mode": r["mode"],
                    "n": int(r["n"]),
                    "avg_latency_ms": _num(r["avg_latency_ms"]),
                    "p95_latency_ms": _num(r["p95_latency_ms"]),
                    "errors": int(r["errors"] or 0),
                }
                for r in guardrails
            ],
            "timeseries": [
                {"bucket": _iso(r["bucket"]), "decision": r["decision"], "requests": int(r["requests"])} for r in series
            ],
        }


def _iso(v: Any) -> str:
    return v.isoformat() if hasattr(v, "isoformat") else str(v)
