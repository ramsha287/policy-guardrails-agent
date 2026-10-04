"""Runs every service-level flow from test_services.py and test_discovery.py against PostgreSQL
(PgStore + migrations).

Enabled when POSTGRES_TEST_DSN is set (CI does this).
"""

import inspect
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from tests import test_discovery as discovery_flows
from tests import test_services as flows

DSN = os.environ.get("POSTGRES_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="POSTGRES_TEST_DSN not set")
SERVICE_DIR = Path(__file__).resolve().parents[1]
FLOWS = sorted(n for n in dir(flows) if n.startswith("test_"))
# discovery flows that need no pytest fixtures (the DNS one reads files from tmp_path)
DISCOVERY_FLOWS = sorted(
    n
    for n in dir(discovery_flows)
    if n.startswith("test_") and not inspect.signature(getattr(discovery_flows, n)).parameters
)
INVENTORY_TABLES = "findings, edges, entities, observations, sync_runs, connectors"
TABLES = (
    "change_log, environment_state, snapshots, catalog_versions, publish_requests, reviews, admin_keys, gateways, "
    "assignments, guardrail_versions, score_modifiers, action_catalog, agent_profiles, api_keys, tenants"
)


@pytest.fixture(scope="module")
def migrated():
    env = {**os.environ, "POSTGRES_DSN": DSN}
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=SERVICE_DIR, env=env, check=True)


@pytest.mark.parametrize("module,flow", [(flows, f) for f in FLOWS] + [(discovery_flows, f) for f in DISCOVERY_FLOWS])
async def test_flow_on_postgres(module, flow, migrated, monkeypatch):
    from sqlalchemy import text

    from app.db.session import make_engine, make_sessionmaker
    from app.domain.crypto import PayloadCipher
    from app.events import MemoryPublisher
    from app.services.context import Ctx, Policy
    from app.store.postgres import PgStore

    engine = make_engine(DSN)
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {', '.join('inventory.' + t.strip() for t in INVENTORY_TABLES.split(','))}"))
        await conn.execute(text(f"TRUNCATE {', '.join('control.' + t.strip() for t in TABLES.split(','))} CASCADE"))
    sm = make_sessionmaker(engine)

    def pg_ctx(**policy):
        store, events = PgStore(sm), MemoryPublisher()
        ctx = Ctx(
            store=store, events=events, cipher=PayloadCipher(Fernet.generate_key().decode()), policy=Policy(**policy)
        )
        return ctx, store, events

    monkeypatch.setattr(module, "make_ctx", pg_ctx)
    try:
        result = getattr(module, flow)()
        if hasattr(result, "__await__"):
            await result
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


async def test_gateway_connector_sql_on_postgres():
    """The gateway connector's activity query against an audit table shaped like the gateway's."""
    import json
    from datetime import UTC, datetime, timedelta

    import httpx
    from sqlalchemy import text

    from app.db.session import make_engine, make_sessionmaker
    from app.discovery.connectors.gateway import GatewayConfig, GatewayConnector
    from app.discovery.model import CollectContext

    engine = make_engine(DSN)
    async with engine.begin() as conn:
        await conn.execute(text("CREATE SCHEMA IF NOT EXISTS audit"))
        await conn.execute(text("DROP TABLE IF EXISTS audit.audit_events"))
        await conn.execute(
            text(
                "CREATE TABLE audit.audit_events (created_at timestamptz NOT NULL, tenant_id varchar(64) NOT NULL,"
                " environment varchar(16) NOT NULL, agent_id varchar(128) NOT NULL, stage varchar(16) NOT NULL,"
                " action varchar(128) NOT NULL, decision varchar(16) NOT NULL, assurance varchar(4),"
                " descriptor jsonb)"
            )
        )
        now = datetime.now(UTC)
        sql_read = {"kind": "sql", "verb": "read", "target": "public.t"}
        send = {"kind": "http", "verb": "send", "destination": "external", "destination_host": "evil.org"}
        rows = [
            (now - timedelta(hours=1), "acme", "input", "llm.chat", "allow", None),
            (now - timedelta(hours=1), "acme", "tool", "db.query", "allow", sql_read),
            (now - timedelta(hours=2), "acme", "tool", "http.post", "block", send),
            (now - timedelta(days=3), "acme", "input", "llm.chat", "allow", None),  # outside the window
            (now - timedelta(hours=1), "other", "input", "llm.chat", "allow", None),  # other tenant
        ]
        for created, tenant, stage, action, decision, desc in rows:
            await conn.execute(
                text(
                    "INSERT INTO audit.audit_events VALUES"
                    " (:c, :t, 'production', 'bot', :s, :a, :d, 'A1', CAST(:j AS jsonb))"
                ),
                {
                    "c": created,
                    "t": tenant,
                    "s": stage,
                    "a": action,
                    "d": decision,
                    "j": json.dumps(desc) if desc else None,
                },
            )
    sm = make_sessionmaker(engine)

    async def fetch(sql, params):
        async with sm() as s:
            return [dict(r) for r in (await s.execute(text(sql), params)).mappings().all()]

    ctx = CollectContext(
        tenant_id="acme",
        connector_id="c1",
        environment=None,
        http=httpx.AsyncClient(),
        now=datetime.now(UTC),
        since=None,
        secrets=lambda n: "",
        check_url=None,  # type: ignore[arg-type]
        audit_fetch=fetch,
    )
    try:
        out = [o async for o in GatewayConnector().collect(GatewayConfig(), ctx)]
        assert len(out) == 1
        agent = out[0].entities[0]
        assert agent.managed_volume == 3 and agent.attrs["blocked"] == 1 and agent.attrs["assurance"] == ["A1"]
        assert sorted(e.kind for e in out[0].edges) == ["reads_from", "sends_to", "uses_tool", "uses_tool"]
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA audit CASCADE"))
        await engine.dispose()
