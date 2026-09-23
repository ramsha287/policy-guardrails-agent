"""control schema

Revision ID: 0001
Revises:
Create Date: 2026-09-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "control"
ENV = "environment IN ('dev', 'staging', 'production')"
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {S}")
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('active', 'suspended')", name="ck_tenant_status"),
        schema=S,
    )
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(64), sa.ForeignKey(f"{S}.tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("prefix", sa.String(12), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("environments", postgresql.ARRAY(sa.String())),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("expires_at", TS),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("revoked_at", TS),
        schema=S,
    )
    op.create_index("ix_cp_api_keys_tenant", "api_keys", ["tenant_id"], schema=S)
    op.create_table(
        "agent_profiles",
        sa.Column("tenant_id", sa.String(64), sa.ForeignKey(f"{S}.tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=False),
        sa.Column("base_trust_score", sa.Integer(), nullable=False),
        sa.Column("allowed_tools", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("owner", sa.String(128)),
        sa.Column("updated_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "agent_id"),
        sa.CheckConstraint("base_trust_score BETWEEN 0 AND 100", name="ck_agent_trust"),
        schema=S,
    )
    op.create_table(
        "action_catalog",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(64), sa.ForeignKey(f"{S}.tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource_pattern", sa.String(256), nullable=False),
        sa.Column("base_risk_score", sa.Integer(), nullable=False),
        sa.UniqueConstraint("tenant_id", "action", "resource_pattern", name="uq_cp_action"),
        sa.CheckConstraint("base_risk_score BETWEEN 0 AND 100", name="ck_action_risk"),
        schema=S,
    )
    op.create_index("ix_cp_action_tenant", "action_catalog", ["tenant_id"], schema=S)
    op.create_table(
        "score_modifiers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(64), sa.ForeignKey(f"{S}.tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("value", sa.String(64), nullable=False),
        sa.Column("delta", sa.Integer(), nullable=False),
        sa.UniqueConstraint("tenant_id", "kind", "value", name="uq_cp_modifier"),
        sa.CheckConstraint("kind IN ('classification', 'environment')", name="ck_modifier_kind"),
        schema=S,
    )
    op.create_index("ix_cp_modifier_tenant", "score_modifiers", ["tenant_id"], schema=S)
    op.create_table(
        "guardrail_versions",
        sa.Column("guardrail_id", sa.String(128), nullable=False),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("manifest", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("conformance_report", postgresql.JSONB()),
        sa.Column("created_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("guardrail_id", "version"),
        sa.CheckConstraint("status IN ('validated', 'deprecated')", name="ck_version_status"),
        schema=S,
    )
    op.create_table(
        "assignments",
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("id", sa.String(128), nullable=False),
        sa.Column("order", sa.Integer(), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("environment", "id"),
        sa.CheckConstraint(ENV, name="ck_assignment_env"),
        schema=S,
    )
    op.create_table(
        "snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("etag", sa.String(40), nullable=False),
        sa.Column("published_at", TS, nullable=False),
        sa.Column("published_by", sa.String(255), nullable=False),
        sa.Column("approved_by", sa.String(255)),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("rolled_back_from", sa.String(64)),
        sa.UniqueConstraint("environment", "version", name="uq_snapshot_version"),
        sa.CheckConstraint(ENV, name="ck_snapshot_env"),
        schema=S,
    )
    op.create_index("ix_snapshots_env_time", "snapshots", ["environment", "published_at"], schema=S)
    op.create_table(
        "environment_state",
        sa.Column("environment", sa.String(16), primary_key=True),
        sa.Column("current_snapshot_id", sa.String(36), sa.ForeignKey(f"{S}.snapshots.id"), nullable=False),
        sa.CheckConstraint(ENV, name="ck_state_env"),
        schema=S,
    )
    op.create_table(
        "catalog_versions",
        sa.Column("seq", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), nullable=False, unique=True),
        sa.Column("version", sa.String(64), nullable=False, unique=True),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("etag", sa.String(40), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("published_at", TS, nullable=False),
        schema=S,
    )
    op.create_table(
        "publish_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("base_version", sa.String(64)),
        sa.Column("rolled_back_from", sa.String(64)),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("requested_by_key", sa.String(36), nullable=False),
        sa.Column("requested_at", TS, nullable=False),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("decided_by", sa.String(255)),
        sa.Column("decided_at", TS),
        sa.Column("decision_note", sa.Text(), nullable=False, server_default=""),
        sa.Column("published_version", sa.String(64)),
        sa.CheckConstraint(ENV, name="ck_request_env"),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'stale')", name="ck_request_status"
        ),
        schema=S,
    )
    op.create_index("ix_publish_requests_env", "publish_requests", ["environment"], schema=S)
    op.create_table(
        "reviews",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("stage", sa.String(16), nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=False),
        sa.Column("guardrail_id", sa.String(128), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("preview", sa.Text(), nullable=False),
        sa.Column("payload_enc", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reviewer", sa.String(255)),
        sa.Column("decision_note", sa.Text(), nullable=False, server_default=""),
        sa.Column("raw_viewed_by", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("decided_at", TS),
        sa.Column("expires_at", TS, nullable=False),
        sa.CheckConstraint("status IN ('pending', 'approved', 'rejected')", name="ck_review_status"),
        schema=S,
    )
    op.create_index("ix_reviews_tenant_status", "reviews", ["tenant_id", "status", "created_at"], schema=S)
    op.create_table(
        "admin_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("prefix", sa.String(12), nullable=False),
        sa.Column("roles", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("tenant_id", sa.String(64)),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        schema=S,
    )
    op.create_table(
        "gateways",
        sa.Column("gateway_id", sa.String(128), primary_key=True),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("snapshot_version", sa.String(64)),
        sa.Column("catalog_version", sa.String(64)),
        sa.Column("last_error", sa.Text()),
        sa.Column("installed", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        schema=S,
    )
    op.create_table(
        "change_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("entity", sa.String(64), nullable=False),
        sa.Column("entity_id", sa.String(255), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("before", postgresql.JSONB()),
        sa.Column("after", postgresql.JSONB()),
        sa.Column("at", TS, nullable=False),
        schema=S,
    )
    op.create_index("ix_change_entity", "change_log", ["entity", "entity_id"], schema=S)
    # The change log and published snapshots are history: rows are never updated or deleted.
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION {S}.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION '%.% is append-only', TG_TABLE_SCHEMA, TG_TABLE_NAME;
        END $$;
        """
    )
    for table in ("change_log", "snapshots", "catalog_versions"):
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {S}.{table} "
            f"FOR EACH ROW EXECUTE FUNCTION {S}.reject_mutation()"
        )


def downgrade() -> None:
    op.execute(f"DROP SCHEMA IF EXISTS {S} CASCADE")
