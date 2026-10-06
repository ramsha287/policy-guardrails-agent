"""tenant advisor data policy (which data classes hosted advisors may see)

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Empty = hosted advisors never see this tenant's requests (the default).
    op.add_column(
        "tenants",
        sa.Column("advisor_data_classes", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        schema="control",
    )


def downgrade() -> None:
    op.drop_column("tenants", "advisor_data_classes", schema="control")
