"""Runs every service-level flow from test_services.py against PostgreSQL (PgStore + migration).

Enabled when POSTGRES_TEST_DSN is set (CI does this).
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from tests import test_services as flows

DSN = os.environ.get("POSTGRES_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="POSTGRES_TEST_DSN not set")
SERVICE_DIR = Path(__file__).resolve().parents[1]
FLOWS = sorted(n for n in dir(flows) if n.startswith("test_"))
TABLES = (
    "change_log, environment_state, snapshots, catalog_versions, publish_requests, reviews, admin_keys, gateways, "
    "assignments, guardrail_versions, score_modifiers, action_catalog, agent_profiles, api_keys, tenants"
)


@pytest.fixture(scope="module")
def migrated():
    env = {**os.environ, "POSTGRES_DSN": DSN}
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=SERVICE_DIR, env=env, check=True)


@pytest.mark.parametrize("flow", FLOWS)
async def test_flow_on_postgres(flow, migrated, monkeypatch):
    from sqlalchemy import text

    from app.db.session import make_engine, make_sessionmaker
    from app.domain.crypto import PayloadCipher
    from app.events import MemoryPublisher
    from app.services.context import Ctx, Policy
    from app.store.postgres import PgStore

    engine = make_engine(DSN)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {', '.join('control.' + t.strip() for t in TABLES.split(','))} CASCADE"))
    sm = make_sessionmaker(engine)

    def pg_ctx(**policy):
        store, events = PgStore(sm), MemoryPublisher()
        ctx = Ctx(
            store=store, events=events, cipher=PayloadCipher(Fernet.generate_key().decode()), policy=Policy(**policy)
        )
        return ctx, store, events

    monkeypatch.setattr(flows, "make_ctx", pg_ctx)
    try:
        await getattr(flows, flow)()
    finally:
        await engine.dispose()


async def test_history_tables_are_append_only(migrated):
    from sqlalchemy import text

    from app.db.session import make_engine

    engine = make_engine(DSN)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO control.change_log (entity, entity_id, action, actor, at) "
                    "VALUES ('t', '1', 'x', 'test', now())"
                )
            )
        with pytest.raises(Exception, match="append-only"):
            async with engine.begin() as conn:
                await conn.execute(text("UPDATE control.change_log SET actor = 'tamper'"))
    finally:
        await engine.dispose()


async def test_analytics_sql_on_postgres():
    """The analytics queries against an audit table shaped like the gateway's (columns they use)."""
    import json
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import text

    from app.db.session import make_engine, make_sessionmaker
    from app.services.analytics import AnalyticsService
    from tests.helpers import ALICE

    engine = make_engine(DSN)
    async with engine.begin() as conn:
        await conn.execute(text("CREATE SCHEMA IF NOT EXISTS audit"))
        await conn.execute(text("DROP TABLE IF EXISTS audit.audit_events"))
        await conn.execute(
            text(
                "CREATE TABLE audit.audit_events (created_at timestamptz NOT NULL, tenant_id varchar(64) NOT NULL,"
                " stage varchar(16) NOT NULL, environment varchar(16) NOT NULL, decision varchar(16) NOT NULL,"
                " policy_allow boolean NOT NULL, guardrail_results jsonb NOT NULL DEFAULT '[]',"
                " latency_ms double precision NOT NULL)"
            )
        )
        result = {
            "guardrail_id": "ai-gateway-pii",
            "version": "1.1.0",
            "decision": "modify",
            "mode": "enforce",
            "latency_ms": 12.5,
            "error": None,
        }
        now = datetime.now(UTC)
        for created, env, allow, results in (
            (now - timedelta(hours=1), "dev", True, [result]),
            (now - timedelta(hours=2), "dev", False, []),
            (now - timedelta(days=40), "dev", True, [result]),
        ):
            await conn.execute(
                text("INSERT INTO audit.audit_events VALUES (:c, 'acme', 'input', :e, :d, :a, CAST(:r AS jsonb), 20)"),
                {"c": created, "e": env, "d": "modify" if allow else "block", "a": allow, "r": json.dumps(results)},
            )
    sm = make_sessionmaker(engine)

    async def fetch(sql, params):
        async with sm() as s:
            return [dict(r) for r in (await s.execute(text(sql), params)).mappings().all()]

    try:
        out = await AnalyticsService(fetch).guardrails(ALICE, environment="dev", tenant_id="acme", hours=24)
        assert out["summary"]["requests"] == 2 and out["summary"]["policy_denied"] == 1
        assert out["rows"][0]["n"] == 1 and out["rows"][0]["p95_latency_ms"] == 12.5
        assert sum(p["requests"] for p in out["timeseries"]) == 2
        everything = await AnalyticsService(fetch).guardrails(ALICE, hours=24 * 60)
        assert everything["summary"]["requests"] == 3
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA audit CASCADE"))
        await engine.dispose()
