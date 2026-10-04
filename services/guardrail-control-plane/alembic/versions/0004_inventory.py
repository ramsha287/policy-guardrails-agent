"""agent discovery and inventory (schema `inventory`)

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-04

New tables only; nothing existing changes.

- connectors: configured sources (no secrets: credentials are named environment variables)
- sync_runs: one row per connector run, with counts and warnings
- observations: raw evidence, pruned after 90 days
- entities: the resolved inventory (GIN indexes on strong/weak keys for entity resolution)
- edges: temporal relations; a change closes the row (valid_to) and opens a new one
- findings: shadow / unmanaged / stale agents and changed tool definitions
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INV = "inventory"
TS = sa.DateTime(timezone=True)


def _tenant() -> sa.Column:
    return sa.Column(
        "tenant_id", sa.String(64), sa.ForeignKey("control.tenants.id", ondelete="CASCADE"), nullable=False
    )


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {INV}")

    op.create_table(
        "connectors",
        sa.Column("id", sa.String(36), primary_key=True),
        _tenant(),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("environment", sa.String(16)),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("last_run_at", TS),
        sa.Column("last_status", sa.String(16)),
        sa.Column("last_error", sa.Text()),
        sa.Column("lease_owner", sa.String(128)),
        sa.Column("lease_until", TS),
        sa.CheckConstraint("interval_minutes BETWEEN 5 AND 10080", name="ck_connector_interval"),
        schema=INV,
    )
    op.create_index("ix_connectors_tenant_id", "connectors", ["tenant_id"], schema=INV)

    op.create_table(
        "sync_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        _tenant(),
        sa.Column(
            "connector_id", sa.String(36), sa.ForeignKey(f"{INV}.connectors.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("triggered_by", sa.String(255), nullable=False),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("finished_at", TS),
        sa.Column("status", sa.String(16), nullable=False),
        *(
            sa.Column(c, sa.Integer(), nullable=False, server_default="0")
            for c in (
                "observations",
                "entities_created",
                "entities_updated",
                "edges_opened",
                "edges_closed",
                "findings_opened",
                "findings_resolved",
            )
        ),
        sa.Column("warnings", postgresql.ARRAY(sa.Text()), nullable=False, server_default="{}"),
        sa.Column("error", sa.Text()),
        schema=INV,
    )
    op.create_index("ix_sync_runs_connector", "sync_runs", ["connector_id", "started_at"], schema=INV)

    op.create_table(
        "observations",
        sa.Column("id", sa.String(36), primary_key=True),
        _tenant(),
        sa.Column("connector_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("source_ref", sa.Text(), nullable=False),
        sa.Column("observed_at", TS, nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("attrs", postgresql.JSONB(), nullable=False),
        sa.Column("entity_id", sa.String(36)),
        schema=INV,
    )
    op.create_index("ix_observations_entity", "observations", ["tenant_id", "entity_id", "observed_at"], schema=INV)
    op.create_index("ix_observations_time", "observations", ["observed_at"], schema=INV)
    op.create_index("ix_observations_run_id", "observations", ["run_id"], schema=INV)

    op.create_table(
        "entities",
        sa.Column("id", sa.String(36), primary_key=True),
        _tenant(),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("strong_keys", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("weak_keys", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("attrs", postgresql.JSONB(), nullable=False),
        sa.Column("sources", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("environment", sa.String(16)),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("agent_likelihood", sa.String(16), nullable=False),
        sa.Column("reasons", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("registry_agent_id", sa.String(128)),
        sa.Column("owner_guess", sa.String(255)),
        sa.Column("managed_volume", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("direct_volume", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("probable_matches", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("ignored_until", TS),
        sa.Column("ignore_reason", sa.Text()),
        sa.Column("updated_at", TS, nullable=False),
        schema=INV,
    )
    op.create_index("ix_entities_strong_keys", "entities", ["strong_keys"], schema=INV, postgresql_using="gin")
    op.create_index("ix_entities_weak_keys", "entities", ["weak_keys"], schema=INV, postgresql_using="gin")
    op.create_index("ix_entities_tenant_state", "entities", ["tenant_id", "state", "kind"], schema=INV)

    op.create_table(
        "edges",
        sa.Column("id", sa.String(36), primary_key=True),
        _tenant(),
        sa.Column("src", sa.String(36), nullable=False),
        sa.Column("dst", sa.String(36), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("attrs", postgresql.JSONB(), nullable=False),
        sa.Column("source", sa.String(36), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("valid_from", TS, nullable=False),
        sa.Column("valid_to", TS),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("evidence_ref", sa.String(36)),
        schema=INV,
    )
    op.create_index("ix_edges_src", "edges", ["tenant_id", "src", "valid_to"], schema=INV)
    op.create_index("ix_edges_dst", "edges", ["tenant_id", "dst", "valid_to"], schema=INV)
    op.create_index("ix_edges_source", "edges", ["tenant_id", "source", "valid_to"], schema=INV)

    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        _tenant(),
        sa.Column("entity_id", sa.String(36), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(8), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("resolved_at", TS),
        sa.Column("resolved_by", sa.String(255)),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.CheckConstraint("status IN ('open', 'resolved', 'accepted')", name="ck_finding_status"),
        schema=INV,
    )
    op.create_index("ix_findings_tenant_status", "findings", ["tenant_id", "status", "created_at"], schema=INV)
    op.create_index("ix_findings_entity_id", "findings", ["entity_id"], schema=INV)


def downgrade() -> None:
    for table in ("findings", "edges", "entities", "observations", "sync_runs", "connectors"):
        op.drop_table(table, schema=INV)
    op.execute(f"DROP SCHEMA IF EXISTS {INV}")
