"""Decision analytics over the gateway's audit log (`audit.audit_events`), read through `AUDIT_DSN`.

Views over the same window:
- `totals`: requests per stage and decision, request latency (avg, p95) and OPA denials. This
  counts every audited request, including ones OPA denied before any guardrail ran.
- `guardrails`: per guardrail version, stage, decision and mode: count, latency and errors.
- `timeseries`: requests per decision per hour (per day for windows over 72 hours).

- `advisors` (separate endpoint): the advisor pilot - answers per advisor, question, status and
  label, latency, points, and how often an advisor flagged a request the deterministic path
  released (the cases a shadow advisor would add; review those before turning it to enforce).

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


ADVISOR_ANSWERS_SQL = """
SELECT a->>'advisor' AS advisor, a->>'provider' AS provider, a->>'mode' AS mode, a->>'question' AS question,
       a->>'status' AS status, coalesce(a->>'label', 'none') AS label, count(*) AS n,
       avg((a->>'latency_ms')::float) AS avg_latency_ms,
       percentile_cont(0.95) WITHIN GROUP (ORDER BY (a->>'latency_ms')::float) AS p95_latency_ms,
       avg((a->>'confidence')::float) AS avg_confidence,
       sum(coalesce((a->>'points')::int, 0)) AS points,
       sum(CASE WHEN (a->>'verify')::boolean THEN 1 ELSE 0 END) AS verify_requests
  FROM audit.audit_events e
 CROSS JOIN LATERAL jsonb_array_elements(e.risk->'advisors'->'answers') AS a
 WHERE {where} AND jsonb_typeof(e.risk->'advisors'->'answers') = 'array'
 GROUP BY 1, 2, 3, 4, 5, 6
 ORDER BY 1, 4, 5, 6
"""

# One row per (advisor, flagged?, stopped?) over answered questions. "Stopped" = the final outcome
# didn't release the request (deny, hold, verify, quarantine). An advisor counts once per request.
ADVISOR_AGREEMENT_SQL = """
SELECT advisor, mode, flagged, stopped, count(*) AS n FROM (
  SELECT e.request_id, a->>'advisor' AS advisor, a->>'mode' AS mode,
         bool_or(a->>'label' <> 'benign') AS flagged,
         bool_or(e.outcome IN ('deny', 'hold', 'verify', 'quarantine_session')) AS stopped
    FROM audit.audit_events e
   CROSS JOIN LATERAL jsonb_array_elements(e.risk->'advisors'->'answers') AS a
   WHERE {where} AND jsonb_typeof(e.risk->'advisors'->'answers') = 'array' AND a->>'status' = 'answered'
   GROUP BY 1, 2, 3
) x
 GROUP BY 1, 2, 3, 4
 ORDER BY 1, 3, 4
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

    def _window(
        self, p: Principal, environment: str | None, tenant_id: str | None, hours: int
    ) -> tuple[str | None, int, str, dict[str, Any]]:
        if tenant_id is None and not p.is_platform:
            tenant_id = p.tenant_id
        p.require(Permission.READ, tenant_id)
        if self.fetch is None:
            raise AnalyticsUnavailable("analytics needs AUDIT_DSN (read access to the gateway's audit schema)")
        hours = max(1, min(hours, MAX_HOURS))
        params: dict[str, Any] = {"since": utcnow() - timedelta(hours=hours)}
        if environment is not None:
            params["environment"] = environment
        if tenant_id is not None:
            params["tenant_id"] = tenant_id
        return tenant_id, hours, build_filter(environment, tenant_id), params

    async def advisors(
        self, p: Principal, *, environment: str | None = None, tenant_id: str | None = None, hours: int = 24 * 7
    ) -> dict[str, Any]:
        """The advisor pilot over the audit log (answers are recorded in `risk.advisors`)."""
        tenant_id, hours, where, params = self._window(p, environment, tenant_id, hours)
        assert self.fetch is not None
        answers = await self.fetch(ADVISOR_ANSWERS_SQL.format(where=where), params)
        agreement = await self.fetch(ADVISOR_AGREEMENT_SQL.format(where=where), params)

        per: dict[str, dict[str, Any]] = {}
        for r in answers:
            a = per.setdefault(
                r["advisor"],
                {
                    "advisor": r["advisor"],
                    "provider": r["provider"],
                    "mode": r["mode"],
                    "questions": 0,
                    "by_status": {},
                    "by_label": {},
                    "points": 0,
                    "verify_requests": 0,
                },
            )
            n = int(r["n"])
            a["questions"] += n
            a["by_status"][r["status"]] = a["by_status"].get(r["status"], 0) + n
            if r["status"] == "answered":
                a["by_label"][r["label"]] = a["by_label"].get(r["label"], 0) + n
            a["points"] += int(r["points"] or 0)
            a["verify_requests"] += int(r["verify_requests"] or 0)
        for r in agreement:
            a = per.get(r["advisor"])
            if a is None:
                continue
            key = ("flagged" if r["flagged"] else "benign") + "_" + ("stopped" if r["stopped"] else "released")
            m = a.setdefault(
                "agreement", {"flagged_stopped": 0, "flagged_released": 0, "benign_stopped": 0, "benign_released": 0}
            )
            m[key] += int(r["n"])
        for a in per.values():
            answered = a["by_status"].get("answered", 0)
            a["no_signal_rate"] = round(1 - answered / a["questions"], 4) if a["questions"] else 0.0
            a.setdefault(
                "agreement", {"flagged_stopped": 0, "flagged_released": 0, "benign_stopped": 0, "benign_released": 0}
            )
        return {
            "environment": environment,
            "tenant_id": tenant_id,
            "hours": hours,
            "advisors": sorted(per.values(), key=lambda a: a["advisor"]),
            "rows": [
                {
                    "advisor": r["advisor"],
                    "mode": r["mode"],
                    "question": r["question"],
                    "status": r["status"],
                    "label": r["label"],
                    "n": int(r["n"]),
                    "avg_latency_ms": _num(r["avg_latency_ms"]),
                    "p95_latency_ms": _num(r["p95_latency_ms"]),
                    "avg_confidence": _num(r["avg_confidence"], 3),
                }
                for r in answers
            ],
        }

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
