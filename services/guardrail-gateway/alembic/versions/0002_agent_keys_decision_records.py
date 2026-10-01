"""agent-bound API keys and decision records v2

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-01

- guardrail.api_keys.agent_id: the only agent a key may act as (identity assurance A1).
- audit.audit_events: outcome, reason codes, action descriptor, risk assessment, assurance and a
  per-(gateway process, tenant) hash chain. Adding nullable columns to the partitioned parent
  also adds them to every partition; existing rows keep NULLs.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _audit_columns() -> list[sa.Column]:  # fresh Column objects per call (a Column belongs to one table)
    return [
        sa.Column("outcome", sa.String(24)),
        sa.Column("reason_codes", postgresql.ARRAY(sa.String())),
        sa.Column("descriptor", postgresql.JSONB()),
        sa.Column("risk", postgresql.JSONB()),
        sa.Column("assurance", sa.String(4)),
        sa.Column("chain_id", sa.String(64)),
        sa.Column("chain_seq", sa.BigInteger()),
        sa.Column("prev_hash", sa.String(64)),
        sa.Column("record_hash", sa.String(64)),
    ]


def upgrade() -> None:
    op.add_column("api_keys", sa.Column("agent_id", sa.String(128)), schema="guardrail")
    for col in _audit_columns():
        op.add_column("audit_events", col, schema="audit")
    # No index: building one on the partitioned parent locks every partition (blocking audit
    # inserts), and verify-audit-chain scans by created_at anyway.


def downgrade() -> None:
    for col in reversed(_audit_columns()):
        op.drop_column("audit_events", col.name, schema="audit")
    op.drop_column("api_keys", "agent_id", schema="guardrail")
