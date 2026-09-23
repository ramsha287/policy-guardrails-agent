"""initial projects table

Revision ID: 0001
Revises:
Create Date: 2026-05-01

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project_name", sa.String(length=255), nullable=False),
        sa.Column("entities", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("customized", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("redaction_type", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_projects_project_name", "projects", ["project_name"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_projects_project_name", table_name="projects")
    op.drop_table("projects")
