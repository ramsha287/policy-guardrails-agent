"""transactional outbox for decision events

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-02

guardrail.outbox holds events written in the same transaction as the audit rows they describe
(decision.made.v1) plus periodic audit.chain_heads.v1 exports. The relay publishes unpublished
rows (oldest first, FOR UPDATE SKIP LOCKED so replicas share the work) and prunes published rows
after 7 days. The partial index keeps "what is left to publish" cheap however large the table is.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "outbox",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("topic", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("event_id", name="uq_outbox_event_id"),
        schema="guardrail",
    )
    op.create_index(
        "ix_outbox_unpublished",
        "outbox",
        ["id"],
        schema="guardrail",
        postgresql_where=sa.text("published_at IS NULL"),
    )
    op.create_index("ix_outbox_published_at", "outbox", ["published_at"], schema="guardrail")


def downgrade() -> None:
    op.drop_index("ix_outbox_published_at", table_name="outbox", schema="guardrail")
    op.drop_index("ix_outbox_unpublished", table_name="outbox", schema="guardrail")
    op.drop_table("outbox", schema="guardrail")
