"""PostgreSQL tables (schema `control`). Owned by the control plane only."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

SCHEMA = "control"
ENV_CHECK = "environment IN ('dev', 'staging', 'production')"


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (CheckConstraint("status IN ('active', 'suspended')", name="ck_tenant_status"), {"schema": SCHEMA})
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), server_default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ApiKey(Base):
    __tablename__ = "api_keys"
    __table_args__ = {"schema": SCHEMA}
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(12))
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String))
    environments: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Agent(Base):
    __tablename__ = "agent_profiles"
    __table_args__ = (
        PrimaryKeyConstraint("tenant_id", "agent_id"),
        CheckConstraint("base_trust_score BETWEEN 0 AND 100", name="ck_agent_trust"),
        {"schema": SCHEMA},
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE"))
    agent_id: Mapped[str] = mapped_column(String(128))
    base_trust_score: Mapped[int] = mapped_column(Integer)
    allowed_tools: Mapped[list[str]] = mapped_column(ARRAY(String))
    owner: Mapped[str | None] = mapped_column(String(128))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Action(Base):
    __tablename__ = "action_catalog"
    __table_args__ = (
        UniqueConstraint("tenant_id", "action", "resource_pattern", name="uq_cp_action"),
        CheckConstraint("base_risk_score BETWEEN 0 AND 100", name="ck_action_risk"),
        {"schema": SCHEMA},
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(128))
    resource_pattern: Mapped[str] = mapped_column(String(256))
    base_risk_score: Mapped[int] = mapped_column(Integer)


class Modifier(Base):
    __tablename__ = "score_modifiers"
    __table_args__ = (
        UniqueConstraint("tenant_id", "kind", "value", name="uq_cp_modifier"),
        CheckConstraint("kind IN ('classification', 'environment')", name="ck_modifier_kind"),
        {"schema": SCHEMA},
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(64))
    delta: Mapped[int] = mapped_column(Integer)


class GuardrailVersion(Base):
    __tablename__ = "guardrail_versions"
    __table_args__ = (
        PrimaryKeyConstraint("guardrail_id", "version"),
        CheckConstraint("status IN ('validated', 'deprecated')", name="ck_version_status"),
        {"schema": SCHEMA},
    )
    guardrail_id: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(32))
    manifest: Mapped[dict] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(16))
    conformance_report: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Assignment(Base):
    __tablename__ = "assignments"
    __table_args__ = (
        PrimaryKeyConstraint("environment", "id"),
        CheckConstraint(ENV_CHECK, name="ck_assignment_env"),
        {"schema": SCHEMA},
    )
    environment: Mapped[str] = mapped_column(String(16))
    id: Mapped[str] = mapped_column(String(128))
    order: Mapped[int] = mapped_column("order", Integer)
    document: Mapped[dict] = mapped_column(JSONB)  # the Assignment as JSON
    updated_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Snapshot(Base):
    __tablename__ = "snapshots"
    __table_args__ = (
        UniqueConstraint("environment", "version", name="uq_snapshot_version"),
        CheckConstraint(ENV_CHECK, name="ck_snapshot_env"),
        Index("ix_snapshots_env_time", "environment", "published_at"),
        {"schema": SCHEMA},
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    environment: Mapped[str] = mapped_column(String(16))
    version: Mapped[str] = mapped_column(String(64))
    document: Mapped[dict] = mapped_column(JSONB)
    etag: Mapped[str] = mapped_column(String(40))
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    published_by: Mapped[str] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(16))
    rolled_back_from: Mapped[str | None] = mapped_column(String(64))


class EnvironmentState(Base):
    __tablename__ = "environment_state"
    __table_args__ = (CheckConstraint(ENV_CHECK, name="ck_state_env"), {"schema": SCHEMA})
    environment: Mapped[str] = mapped_column(String(16), primary_key=True)
    current_snapshot_id: Mapped[str] = mapped_column(ForeignKey(f"{SCHEMA}.snapshots.id"))


class Catalog(Base):
    __tablename__ = "catalog_versions"
    __table_args__ = {"schema": SCHEMA}
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    version: Mapped[str] = mapped_column(String(64), unique=True)
    document: Mapped[dict] = mapped_column(JSONB)
    etag: Mapped[str] = mapped_column(String(40))
    content_hash: Mapped[str] = mapped_column(String(64))
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PublishRequest(Base):
    __tablename__ = "publish_requests"
    __table_args__ = (
        CheckConstraint(ENV_CHECK, name="ck_request_env"),
        CheckConstraint("status IN ('pending', 'approved', 'rejected', 'expired', 'stale')", name="ck_request_status"),
        {"schema": SCHEMA},
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    environment: Mapped[str] = mapped_column(String(16), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    document: Mapped[dict] = mapped_column(JSONB)
    base_version: Mapped[str | None] = mapped_column(String(64))
    rolled_back_from: Mapped[str | None] = mapped_column(String(64))
    requested_by: Mapped[str] = mapped_column(String(255))
    requested_by_key: Mapped[str] = mapped_column(String(36))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    note: Mapped[str] = mapped_column(Text, server_default="")
    status: Mapped[str] = mapped_column(String(16))
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str] = mapped_column(Text, server_default="")
    published_version: Mapped[str | None] = mapped_column(String(64))


class Review(Base):
    __tablename__ = "reviews"
    __table_args__ = (
        CheckConstraint("status IN ('pending', 'approved', 'rejected')", name="ck_review_status"),
        Index("ix_reviews_tenant_status", "tenant_id", "status", "created_at"),
        {"schema": SCHEMA},
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64))
    environment: Mapped[str] = mapped_column(String(16))
    request_id: Mapped[str] = mapped_column(String(64))
    stage: Mapped[str] = mapped_column(String(16))
    agent_id: Mapped[str] = mapped_column(String(128))
    guardrail_id: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[int] = mapped_column(Integer)
    preview: Mapped[str] = mapped_column(Text)
    payload_enc: Mapped[bytes] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(String(16))
    reviewer: Mapped[str | None] = mapped_column(String(255))
    decision_note: Mapped[str] = mapped_column(Text, server_default="")
    raw_viewed_by: Mapped[list[str]] = mapped_column(ARRAY(String))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AdminKey(Base):
    __tablename__ = "admin_keys"
    __table_args__ = {"schema": SCHEMA}
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(12))
    roles: Mapped[list[str]] = mapped_column(ARRAY(String))
    tenant_id: Mapped[str | None] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Gateway(Base):
    __tablename__ = "gateways"
    __table_args__ = {"schema": SCHEMA}
    gateway_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    environment: Mapped[str] = mapped_column(String(16))
    snapshot_version: Mapped[str | None] = mapped_column(String(64))
    catalog_version: Mapped[str | None] = mapped_column(String(64))
    last_error: Mapped[str | None] = mapped_column(Text)
    installed: Mapped[list[str]] = mapped_column(ARRAY(String))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Change(Base):
    __tablename__ = "change_log"
    __table_args__ = (Index("ix_change_entity", "entity", "entity_id"), {"schema": SCHEMA})
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    entity: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(255))
    before: Mapped[dict | None] = mapped_column(JSONB)
    after: Mapped[dict | None] = mapped_column(JSONB)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
