"""bind gateway API keys to one agent (identity assurance A1)

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-01
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
    # NULL = a legacy key that may act as any agent_id the caller claims (A0).
    op.add_column("api_keys", sa.Column("agent_id", sa.String(128)), schema="control")
    # What each gateway can do (from its heartbeat). Binding keys needs every live gateway to
    # report "agent_bound_keys": older gateways reject catalogs that contain bound keys.
    op.add_column(
        "gateways",
        sa.Column("capabilities", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        schema="control",
    )


def downgrade() -> None:
    op.drop_column("gateways", "capabilities", schema="control")
    op.drop_column("api_keys", "agent_id", schema="control")
