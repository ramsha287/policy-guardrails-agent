"""Analytics service: filters, tenant scoping and aggregation (SQL itself runs in test_postgres_store)."""

from datetime import UTC, datetime

import pytest

from app.domain.rbac import Forbidden
from app.services.analytics import AnalyticsService, AnalyticsUnavailable, build_filter
from tests.helpers import ACME_REVIEWER, ALICE


class FakeDb:
    def __init__(self):
        self.calls = []

    async def fetch(self, sql, params):
        self.calls.append((sql, params))
        if "percentile_cont(0.95) WITHIN GROUP (ORDER BY e.latency_ms)" in sql:
            return [
                {
                    "stage": "input",
                    "decision": "allow",
                    "requests": 3,
                    "avg_latency_ms": 20.123,
                    "p95_latency_ms": 30.0,
                    "policy_denied": 0,
                },
                {
                    "stage": "tool",
                    "decision": "block",
                    "requests": 1,
                    "avg_latency_ms": 5.0,
                    "p95_latency_ms": 5.0,
                    "policy_denied": 1,
                },
            ]
        if "jsonb_array_elements" in sql:
            return [
                {
                    "guardrail_id": "ai-gateway-pii",
                    "version": "1.1.0",
                    "stage": "input",
                    "decision": "allow",
                    "mode": "enforce",
                    "n": 3,
                    "avg_latency_ms": 10.0,
                    "p95_latency_ms": 12.5,
                    "errors": 0,
                }
            ]
        return [{"bucket": datetime(2026, 9, 24, 6, tzinfo=UTC), "decision": "allow", "requests": 3}]


def test_filter_only_includes_given_filters():
    assert build_filter(None, None) == "e.created_at > :since"
    assert (
        build_filter("dev", "acme")
        == "e.created_at > :since AND e.environment = :environment AND e.tenant_id = :tenant_id"
    )


async def test_summary_and_rows():
    db = FakeDb()
    out = await AnalyticsService(db.fetch).guardrails(ALICE, environment="dev", hours=24)
    assert out["summary"] == {
        "requests": 4,
        "by_decision": {"allow": 3, "block": 1},
        "policy_denied": 1,
        "block_rate": 0.25,
    }
    assert out["totals"][0]["avg_latency_ms"] == 20.12 and out["rows"][0]["p95_latency_ms"] == 12.5
    assert out["timeseries"] == [{"bucket": "2026-09-24T06:00:00+00:00", "decision": "allow", "requests": 3}]
    assert out["bucket"] == "hour"
    sql, params = db.calls[0]
    assert "e.environment = :environment" in sql and "tenant_id" not in params and params["environment"] == "dev"


async def test_environment_is_optional_and_long_windows_use_days():
    db = FakeDb()
    out = await AnalyticsService(db.fetch).guardrails(ALICE, hours=24 * 30)
    assert out["environment"] is None and out["bucket"] == "day"
    assert "date_trunc('day'" in db.calls[2][0] and "environment" not in db.calls[0][1]


async def test_tenant_keys_are_scoped_to_their_tenant():
    db = FakeDb()
    out = await AnalyticsService(db.fetch).guardrails(ACME_REVIEWER)
    assert out["tenant_id"] == "acme" and db.calls[0][1]["tenant_id"] == "acme"
    with pytest.raises(Forbidden):
        await AnalyticsService(db.fetch).guardrails(ACME_REVIEWER, tenant_id="other")


async def test_unconfigured():
    with pytest.raises(AnalyticsUnavailable):
        await AnalyticsService(None).guardrails(ALICE)
