"""guardrail + audit schemas

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


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS guardrail")
    op.execute("CREATE SCHEMA IF NOT EXISTS audit")

    op.create_table(
        "tenants",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('active', 'suspended')", name="ck_tenants_status"),
        schema="guardrail",
    )
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id", sa.String(64), sa.ForeignKey("guardrail.tenants.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("prefix", sa.String(12), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String()), nullable=False, server_default="{guard:invoke}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="guardrail",
    )
    op.create_index("ix_api_keys_tenant", "api_keys", ["tenant_id"], schema="guardrail")
    op.create_table(
        "agent_profiles",
        sa.Column(
            "tenant_id", sa.String(64), sa.ForeignKey("guardrail.tenants.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("agent_id", sa.String(128), nullable=False),
        sa.Column("base_trust_score", sa.Integer(), nullable=False),
        sa.Column("allowed_tools", postgresql.ARRAY(sa.String()), nullable=False, server_default="{*}"),
        sa.Column("owner", sa.String(128)),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("tenant_id", "agent_id"),
        sa.CheckConstraint("base_trust_score BETWEEN 0 AND 100", name="ck_agent_trust_range"),
        schema="guardrail",
    )
    op.create_table(
        "action_catalog",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id", sa.String(64), sa.ForeignKey("guardrail.tenants.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource_pattern", sa.String(256), nullable=False, server_default="*"),
        sa.Column("base_risk_score", sa.Integer(), nullable=False),
        sa.UniqueConstraint("tenant_id", "action", "resource_pattern", name="uq_action_catalog"),
        sa.CheckConstraint("base_risk_score BETWEEN 0 AND 100", name="ck_action_risk_range"),
        schema="guardrail",
    )
    op.create_index("ix_action_catalog_tenant", "action_catalog", ["tenant_id"], schema="guardrail")
    op.create_table(
        "score_modifiers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id", sa.String(64), sa.ForeignKey("guardrail.tenants.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("value", sa.String(64), nullable=False),
        sa.Column("delta", sa.Integer(), nullable=False),
        sa.UniqueConstraint("tenant_id", "kind", "value", name="uq_score_modifier"),
        sa.CheckConstraint("kind IN ('classification', 'environment')", name="ck_modifier_kind"),
        schema="guardrail",
    )
    op.create_index("ix_score_modifiers_tenant", "score_modifiers", ["tenant_id"], schema="guardrail")

    # Append-only, monthly-partitioned audit log.
    op.execute(
        """
        CREATE TABLE audit.audit_events (
            id                uuid         NOT NULL,
            created_at        timestamptz  NOT NULL DEFAULT now(),
            tenant_id         varchar(64)  NOT NULL,
            request_id        varchar(64)  NOT NULL,
            trace_id          varchar(32)  NOT NULL,
            stage             varchar(16)  NOT NULL,
            environment       varchar(16)  NOT NULL,
            agent_id          varchar(128) NOT NULL,
            user_id           varchar(128),
            session_id        varchar(128),
            action            varchar(128) NOT NULL,
            resource          varchar(256),
            decision          varchar(16)  NOT NULL,
            reason            text         NOT NULL,
            risk_score        integer      NOT NULL,
            trust_score       integer      NOT NULL,
            policy_allow      boolean      NOT NULL,
            policy_reason     text         NOT NULL,
            guardrail_results jsonb        NOT NULL DEFAULT '[]'::jsonb,
            payload_sha256    varchar(64)  NOT NULL,
            snapshot_version  varchar(64),
            latency_ms        double precision NOT NULL,
            usage_bytes       bigint       NOT NULL DEFAULT 0,
            PRIMARY KEY (id, created_at)
        ) PARTITION BY RANGE (created_at)
        """
    )
    op.execute("CREATE INDEX ix_audit_tenant_time ON audit.audit_events (tenant_id, created_at DESC)")
    op.execute("CREATE INDEX ix_audit_request ON audit.audit_events (request_id)")

    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit.ensure_partitions(months_ahead integer DEFAULT 3)
        RETURNS void LANGUAGE plpgsql AS $$
        DECLARE
            start_month date := date_trunc('month', now())::date - interval '1 month';
            m date;
            part text;
        BEGIN
            FOR i IN 0..(months_ahead + 1) LOOP
                m := (start_month + (i || ' month')::interval)::date;
                part := format('audit_events_%s', to_char(m, 'YYYY_MM'));
                IF to_regclass('audit.' || part) IS NULL THEN
                    EXECUTE format(
                        'CREATE TABLE audit.%I PARTITION OF audit.audit_events FOR VALUES FROM (%L) TO (%L)',
                        part, m, (m + interval '1 month')::date
                    );
                END IF;
            END LOOP;
        END $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit.drop_partitions_older_than(months integer DEFAULT 12)
        RETURNS integer LANGUAGE plpgsql AS $$
        DECLARE
            cutoff date := (date_trunc('month', now()) - (months || ' month')::interval)::date;
            r record;
            dropped integer := 0;
        BEGIN
            FOR r IN
                SELECT c.relname
                  FROM pg_inherits i
                  JOIN pg_class c ON c.oid = i.inhrelid
                  JOIN pg_class p ON p.oid = i.inhparent
                  JOIN pg_namespace n ON n.oid = p.relnamespace
                 WHERE n.nspname = 'audit' AND p.relname = 'audit_events'
                   AND c.relname ~ '^audit_events_\\d{4}_\\d{2}$'
            LOOP
                IF to_date(substring(r.relname from '\\d{4}_\\d{2}$'), 'YYYY_MM') < cutoff THEN
                    EXECUTE format('DROP TABLE audit.%I', r.relname);
                    dropped := dropped + 1;
                END IF;
            END LOOP;
            RETURN dropped;
        END $$;
        """
    )
    # Append-only: row updates and deletes are rejected for everyone, including the owner.
    # Retention works by dropping whole partitions (DDL), which this trigger does not block.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit.audit_events is append-only';
        END $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_append_only
        BEFORE UPDATE OR DELETE ON audit.audit_events
        FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation()
        """
    )
    op.execute("SELECT audit.ensure_partitions(3)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit.audit_events CASCADE")
    op.execute("DROP FUNCTION IF EXISTS audit.reject_mutation()")
    op.execute("DROP FUNCTION IF EXISTS audit.drop_partitions_older_than(integer)")
    op.execute("DROP FUNCTION IF EXISTS audit.ensure_partitions(integer)")
    op.drop_table("score_modifiers", schema="guardrail")
    op.drop_table("action_catalog", schema="guardrail")
    op.drop_table("agent_profiles", schema="guardrail")
    op.drop_table("api_keys", schema="guardrail")
    op.drop_table("tenants", schema="guardrail")
