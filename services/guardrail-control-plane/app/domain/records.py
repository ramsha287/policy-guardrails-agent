"""Domain records the control plane stores. Storage-agnostic (Postgres or in-memory)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from guardrail_sdk.documents import Assignment, Environment

ENVIRONMENTS: tuple[Environment, ...] = ("dev", "staging", "production")


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class Record(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class TenantRecord(Record):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    name: str
    status: Literal["active", "suspended"] = "active"
    created_at: datetime = Field(default_factory=utcnow)


class ApiKeyRecord(Record):
    id: str = Field(default_factory=new_id)
    tenant_id: str
    name: str
    key_hash: str
    prefix: str
    scopes: list[str] = Field(default_factory=lambda: ["guard:invoke"])
    environments: list[Environment] | None = None
    is_active: bool = True
    expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=utcnow)
    revoked_at: datetime | None = None
    rate_limit_per_minute: int | None = Field(default=None, ge=0)  # None = gateway default, 0 = unlimited


class AgentRecord(Record):
    tenant_id: str
    agent_id: str
    base_trust_score: int = Field(ge=0, le=100)
    allowed_tools: list[str] = Field(default_factory=lambda: ["*"])
    owner: str | None = None
    updated_at: datetime = Field(default_factory=utcnow)


class ActionRecord(Record):
    id: str = Field(default_factory=new_id)
    tenant_id: str
    action: str
    resource_pattern: str = "*"
    base_risk_score: int = Field(ge=0, le=100)


class ModifierRecord(Record):
    id: str = Field(default_factory=new_id)
    tenant_id: str
    kind: Literal["classification", "environment"]
    value: str
    delta: int = Field(ge=-100, le=100)


class GuardrailVersionRecord(Record):
    guardrail_id: str
    version: str
    manifest: dict[str, Any]
    status: Literal["validated", "deprecated"] = "validated"
    source: Literal["gateway", "api"] = "api"
    conformance_report: dict[str, Any] | None = None
    created_at: datetime = Field(default_factory=utcnow)


class AssignmentRecord(Record):
    """Working-set (draft) assignment for one environment. Publishing freezes these into a snapshot."""

    environment: Environment
    assignment: Assignment
    updated_by: str
    updated_at: datetime = Field(default_factory=utcnow)


class SnapshotRecord(Record):
    id: str = Field(default_factory=new_id)
    environment: Environment
    version: str
    document: dict[str, Any]  # SnapshotDoc as JSON
    etag: str
    published_at: datetime = Field(default_factory=utcnow)
    published_by: str
    approved_by: str | None = None
    kind: Literal["publish", "rollback", "import"] = "publish"
    rolled_back_from: str | None = None


class CatalogRecord(Record):
    id: str = Field(default_factory=new_id)
    version: str
    document: dict[str, Any]  # CatalogDoc as JSON
    etag: str
    content_hash: str
    published_at: datetime = Field(default_factory=utcnow)


class PublishRequestRecord(Record):
    id: str = Field(default_factory=new_id)
    environment: Environment
    kind: Literal["publish", "rollback"] = "publish"
    document: dict[str, Any]  # SnapshotDoc to publish (version filled at commit)
    base_version: str | None  # current snapshot when requested; approval fails if it changed
    rolled_back_from: str | None = None
    requested_by: str
    requested_by_key: str  # admin key id; the approver must use a different key
    requested_at: datetime = Field(default_factory=utcnow)
    note: str = ""
    status: Literal["pending", "approved", "rejected", "expired", "stale"] = "pending"
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_note: str = ""
    published_version: str | None = None


class ReviewRecord(Record):
    id: str = Field(default_factory=new_id)
    tenant_id: str
    environment: Environment
    request_id: str
    stage: str
    agent_id: str
    guardrail_id: str
    reason: str
    risk_score: int = 0
    preview: str = ""
    payload_enc: bytes  # encrypted held payload (Fernet)
    status: Literal["pending", "approved", "rejected"] = "pending"
    reviewer: str | None = None
    decision_note: str = ""
    raw_viewed_by: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    decided_at: datetime | None = None
    expires_at: datetime

    def effective_status(self, now: datetime | None = None) -> str:
        if self.status == "pending" and (now or utcnow()) >= self.expires_at:
            return "expired"
        return self.status


class AdminKeyRecord(Record):
    id: str = Field(default_factory=new_id)
    name: str
    key_hash: str
    prefix: str
    roles: list[str]
    tenant_id: str | None = None  # None = platform-wide
    is_active: bool = True
    created_at: datetime = Field(default_factory=utcnow)


class GatewayRecord(Record):
    gateway_id: str
    environment: Environment
    snapshot_version: str | None = None
    catalog_version: str | None = None
    last_error: str | None = None
    installed: list[str] = Field(default_factory=list)  # "id@version"
    last_seen: datetime = Field(default_factory=utcnow)


class ChangeRecord(Record):
    id: int | None = None
    entity: str
    entity_id: str
    action: str
    actor: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    at: datetime = Field(default_factory=utcnow)
