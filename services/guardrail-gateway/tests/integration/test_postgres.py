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


async def test_audit_survives_a_database_outage_via_the_spool(sm, tmp_path):
    """Events that can't be written go to disk and are replayed once Postgres is back (no loss, no dupes)."""
    from app.audit.spool import AuditSpool

    def event(n):
        return {
            "tenant_id": "it-tenant",
            "request_id": f"it-spool-{n}",
            "trace_id": "c" * 32,
            "stage": "input",
            "environment": "dev",
            "agent_id": "bot",
            "user_id": None,
            "session_id": None,
            "action": "llm.chat",
            "resource": None,
            "decision": "allow",
            "reason": "ok",
            "risk_score": 10,
            "trust_score": 75,
            "policy_allow": True,
            "policy_reason": "allowed",
            "guardrail_results": [{"guardrail_id": "g", "latency_ms": 1.0, "error": None}],
            "payload_sha256": "0" * 64,
            "snapshot_version": "v1",
            "latency_ms": 3.0,
            "usage_bytes": 10,
        }

    spool = AuditSpool(tmp_path)
    down_engine = make_engine("postgresql+asyncpg://nobody:wrong@127.0.0.1:1/none")
    down = AuditWriter(make_sessionmaker(down_engine), flush_seconds=0.01, spool=spool, maintenance=False)
    for n in range(3):
        down.submit(event(n))
    await down.stop()  # drain fails: the events go to the spool instead of being dropped
    await down_engine.dispose()
    assert spool.files()

    up = AuditWriter(sm, spool=spool, maintenance=False)
    assert await up.replay_spool() == 3 and spool.files() == []
    assert await up.replay_spool() == 0  # nothing left; replaying twice never duplicates
    async with sm() as s:
        n = (
            await s.execute(text("SELECT count(*) FROM audit.audit_events WHERE request_id LIKE 'it-spool-%'"))
        ).scalar()
    assert n == 3


async def test_outbox_written_with_the_audit_rows_and_relayed(sm):
    """decision.made.v1 rows are written in the audit transaction; the relay publishes and marks them."""
    from app.audit.chain import AuditChain
    from app.events.relay import OutboxRelay

    class Sink:
        name = "test"

        def __init__(self, fail=False):
            self.fail, self.got = fail, []

        async def publish(self, events):
            if self.fail:
                raise ConnectionError("sink down")
            self.got.extend(events)

    async with sm() as s:  # start from an empty outbox (other tests may have left rows)
        await s.execute(text("DELETE FROM guardrail.outbox"))
        await s.commit()

    chain = AuditChain()
    writer = AuditWriter(sm, flush_seconds=0.02, maintenance=False, chain=chain, outbox_source="gw/it")
    await writer.start()
    for n in range(3):
        writer.submit(
            {
                "tenant_id": "it-outbox", "request_id": f"it-ob-{n}", "trace_id": "d" * 32, "stage": "tool",
                "environment": "dev", "agent_id": "bot", "user_id": "u1", "session_id": "s1", "action": "db.query",
                "resource": None, "decision": "allow", "reason": "ok", "risk_score": 10, "trust_score": 75,
                "policy_allow": True, "policy_reason": "allowed", "guardrail_results": [], "payload_sha256": "0" * 64,
                "snapshot_version": "v1", "latency_ms": 1.0, "usage_bytes": 0, "outcome": "allow",
                "reason_codes": ["NEW_SESSION"], "descriptor": {"kind": "sql"},
                "risk": {"band": "low", "mode": "shadow"}, "assurance": "A1",
            }
        )  # fmt: skip
    await writer.stop()

    failing = Sink(fail=True)
    relay = OutboxRelay(sm, [failing], source="gw/it", heads=writer.written_heads)
    with pytest.raises(ConnectionError):
        await relay.publish_once()
    async with sm() as s:
        left = (await s.execute(text("SELECT count(*) FROM guardrail.outbox WHERE published_at IS NULL"))).scalar()
    assert left == 3  # nothing lost when a sink is down

    sink = Sink()
    relay = OutboxRelay(sm, [sink], source="gw/it", heads=writer.written_heads)
    assert await relay.publish_once() == 3
    assert await relay.publish_once() == 0
    ev = sink.got[0]
    assert ev["type"] == "io.guardrail.decision.made.v1" and ev["tenantid"] == "it-outbox" and ev["source"] == "gw/it"
    assert ev["data"]["request_id"] == "it-ob-0" and ev["data"]["chain_seq"] == 1 and ev["data"]["risk_band"] == "low"
    assert len({e["id"] for e in sink.got}) == 3

    assert await relay.export_chain_heads() == 1
    assert await relay.publish_once() == 1
    heads = sink.got[-1]
    assert heads["type"] == "io.guardrail.audit.chain_heads.v1" and heads["data"]["chain_seq"] == 3
    assert heads["data"]["record_hash"] == chain.heads()["it-outbox"][1]  # all were committed

    async with sm() as s:
        await s.execute(text("UPDATE guardrail.outbox SET published_at = now() - interval '8 days'"))
        await s.commit()
    assert await relay.prune() == 4
