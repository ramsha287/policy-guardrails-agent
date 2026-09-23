"""Tables owned by the guardrail gateway.

`guardrail.*` holds tenants, gateway API keys and the scoring catalog. These move to the
control-plane service in phase 4; the gateway will then read them through the snapshot.
`audit.*` holds the append-only decision log (monthly partitions, 12-month retention).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'suspended')", name="ck_tenants_status"),
        {"schema": "guardrail"},
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class GatewayApiKey(Base):
    __tablename__ = "api_keys"
    __table_args__ = {"schema": "guardrail"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("guardrail.tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, server_default="{guard:invoke}")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AgentProfile(Base):
    __tablename__ = "agent_profiles"
    __table_args__ = (
        PrimaryKeyConstraint("tenant_id", "agent_id"),
        CheckConstraint("base_trust_score BETWEEN 0 AND 100", name="ck_agent_trust_range"),
        {"schema": "guardrail"},
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("guardrail.tenants.id", ondelete="CASCADE"))
    agent_id: Mapped[str] = mapped_column(String(128))
    base_trust_score: Mapped[int] = mapped_column(Integer, nullable=False)
    allowed_tools: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, server_default="{*}")
    owner: Mapped[str | None] = mapped_column(String(128))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ActionCatalogEntry(Base):
    __tablename__ = "action_catalog"
    __table_args__ = (
        UniqueConstraint("tenant_id", "action", "resource_pattern", name="uq_action_catalog"),
        CheckConstraint("base_risk_score BETWEEN 0 AND 100", name="ck_action_risk_range"),
        {"schema": "guardrail"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("guardrail.tenants.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_pattern: Mapped[str] = mapped_column(String(256), nullable=False, server_default="*")
    base_risk_score: Mapped[int] = mapped_column(Integer, nullable=False)


class ScoreModifier(Base):
    __tablename__ = "score_modifiers"
    __table_args__ = (
        UniqueConstraint("tenant_id", "kind", "value", name="uq_score_modifier"),
        CheckConstraint("kind IN ('classification', 'environment')", name="ck_modifier_kind"),
        {"schema": "guardrail"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("guardrail.tenants.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(64), nullable=False)
    delta: Mapped[int] = mapped_column(Integer, nullable=False)


class AuditEvent(Base):
    """Partitioned by month on created_at (see migration). Never stores raw payload text."""

    __tablename__ = "audit_events"
    __table_args__ = (PrimaryKeyConstraint("id", "created_at"), {"schema": "audit"})

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(32), nullable=False)
    stage: Mapped[str] = mapped_column(String(16), nullable=False)
    environment: Mapped[str] = mapped_column(String(16), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(128))
    session_id: Mapped[str | None] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(256))
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    trust_score: Mapped[int] = mapped_column(Integer, nullable=False)
    policy_allow: Mapped[bool] = mapped_column(Boolean, nullable=False)
    policy_reason: Mapped[str] = mapped_column(Text, nullable=False)
    guardrail_results: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, server_default="[]")
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_version: Mapped[str | None] = mapped_column(String(64))
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    usage_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
