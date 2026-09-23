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
