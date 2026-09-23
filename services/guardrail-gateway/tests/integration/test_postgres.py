"""Runs against a real PostgreSQL. Set POSTGRES_TEST_DSN (postgresql+asyncpg://...) to enable."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import text

from app import cli
from app.audit.writer import AuditWriter
from app.db.session import make_engine, make_sessionmaker
from app.gateway.auth import hash_key
from app.repositories.api_keys import PgApiKeyStore
from app.repositories.catalog import PgCatalogStore

DSN = os.environ.get("POSTGRES_TEST_DSN")
pytestmark = [pytest.mark.integration, pytest.mark.skipif(not DSN, reason="POSTGRES_TEST_DSN not set")]
SERVICE_DIR = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module", autouse=True)
def migrate():
    env = {**os.environ, "POSTGRES_DSN": DSN}
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=SERVICE_DIR, env=env, check=True)


@pytest.fixture
async def sm():
    engine = make_engine(DSN)
    yield make_sessionmaker(engine)
    await engine.dispose()


async def test_keys_and_catalog_roundtrip(sm):
    await cli.create_tenant(sm, "it-tenant", "Integration")
    raw = await cli.create_api_key(sm, "it-tenant", "it-key", ["guard:invoke"])
    await cli.upsert_agent(sm, "it-tenant", "bot", 70, ["crm.lookup"])
    await cli.upsert_agent(sm, "it-tenant", "bot", 75, ["crm.lookup"])  # upsert
    await cli.upsert_action(sm, "it-tenant", "crm.lookup", "*", 30)
    await cli.upsert_modifier(sm, "it-tenant", "classification", "PII", 20)

    principal = await PgApiKeyStore(sm).lookup(hash_key(raw))
    assert principal and principal.tenant_id == "it-tenant" and "guard:invoke" in principal.scopes
    assert await PgApiKeyStore(sm).lookup(hash_key("wrong")) is None

    cat = await PgCatalogStore(sm).load("it-tenant")
    assert cat.agent("bot").base_trust_score == 75
    assert cat.action_rule("crm.lookup", "anything").base_risk_score == 30
    assert cat.modifier("classification", "PII") == 20


async def test_audit_is_written_partitioned_and_append_only(sm):
    writer = AuditWriter(sm, flush_seconds=0.05)
    await writer.start()
    writer.submit(
        {
            "tenant_id": "it-tenant",
            "request_id": "it-req-1",
            "trace_id": "b" * 32,
            "stage": "input",
            "environment": "dev",
            "agent_id": "bot",
            "user_id": None,
            "session_id": None,
            "action": "llm.chat",
            "resource": None,
            "decision": "modify",
            "reason": "redacted",
            "risk_score": 40,
            "trust_score": 75,
            "policy_allow": True,
            "policy_reason": "allowed",
            "guardrail_results": [],
            "payload_sha256": "0" * 64,
            "snapshot_version": "v1",
            "latency_ms": 12.5,
            "usage_bytes": 100,
        }
    )
    await writer.stop()
    async with sm() as s:
        n = (await s.execute(text("SELECT count(*) FROM audit.audit_events WHERE request_id='it-req-1'"))).scalar()
        parts_sql = (
            "SELECT count(*) FROM pg_inherits i JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'audit_events'"
        )
        parts = (await s.execute(text(parts_sql))).scalar()
    assert n == 1 and parts >= 4
    async with sm() as s:
        with pytest.raises(Exception, match="append-only"):
            await s.execute(text("UPDATE audit.audit_events SET reason='x' WHERE request_id='it-req-1'"))


async def test_retention_drops_only_old_partitions(sm):
    async with sm() as s:
        await s.execute(
            text(
                "CREATE TABLE IF NOT EXISTS audit.audit_events_2000_01 PARTITION OF audit.audit_events "
                "FOR VALUES FROM ('2000-01-01') TO ('2000-02-01')"
            )
        )
        dropped = (await s.execute(text("SELECT audit.drop_partitions_older_than(12)"))).scalar()
        await s.commit()
        remaining = (await s.execute(text("SELECT to_regclass('audit.audit_events_2000_01')"))).scalar()
    assert dropped >= 1 and remaining is None
