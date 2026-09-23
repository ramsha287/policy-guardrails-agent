"""api_keys.scope (client | service)

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-23

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("api_keys", sa.Column("scope", sa.String(length=16), nullable=False, server_default="client"))
    op.create_check_constraint("ck_api_keys_scope", "api_keys", "scope IN ('client', 'service')")


def downgrade() -> None:
    op.drop_constraint("ck_api_keys_scope", "api_keys", type_="check")
    op.drop_column("api_keys", "scope")
