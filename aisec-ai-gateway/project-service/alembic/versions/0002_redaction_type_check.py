"""add redaction_type check constraint

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-01

"""
from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_projects_redaction_type",
        "projects",
        "redaction_type IN ('replace', 'mask', 'hash')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_projects_redaction_type", "projects", type_="check")
