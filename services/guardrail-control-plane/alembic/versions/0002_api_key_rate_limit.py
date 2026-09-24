"""per-key rate limit for gateway API keys

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # NULL = the gateway's default (GUARD_RATE_LIMIT_PER_MINUTE); 0 = unlimited for this key.
    op.add_column("api_keys", sa.Column("rate_limit_per_minute", sa.Integer()), schema="control")
    op.create_check_constraint(
        "ck_api_key_rate_limit",
        "api_keys",
        "rate_limit_per_minute IS NULL OR rate_limit_per_minute >= 0",
        schema="control",
    )


def downgrade() -> None:
    op.drop_constraint("ck_api_key_rate_limit", "api_keys", schema="control")
    op.drop_column("api_keys", "rate_limit_per_minute", schema="control")
