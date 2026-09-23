import uuid
from datetime import datetime

from sqlalchemy import ARRAY, CheckConstraint, DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from database.base import Base


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint(
            "redaction_type IN ('replace', 'mask', 'hash')",
            name="ck_projects_redaction_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_name: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    entities: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    customized: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, default=list)
    redaction_type: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
