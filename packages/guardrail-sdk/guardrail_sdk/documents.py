"""Documents the control plane publishes and the gateway consumes.

- `SnapshotDoc`: the guardrail pipeline for one environment (which guardrail versions run where,
  in what order, in which mode, with which config). Published with two-person approval in
  protected environments.
- `CatalogDoc`: tenants, gateway API-key *hashes*, agent profiles (base trust), the action
  catalog (base risk) and score modifiers. Published automatically on every catalog change so
  key revocations and score edits take effect within seconds.

Both are immutable once published and identified by `version`; the gateway caches the last
good copy on disk so it keeps running when the control plane is down.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import Stage

Environment = Literal["dev", "staging", "production"]


class Assignment(BaseModel):
    """One guardrail version applied to a scope, stages and environment."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")
    guardrail_id: str
    guardrail_version: str
    scope_type: Literal["global", "tenant", "agent"] = "global"
    scope_id: str | None = None  # tenant id, or "tenant/agent" for agent scope
    stages: list[Stage]
    order: int = 100
    parallel_group: str | None = None
    enabled: bool = True
    mode: Literal["enforce", "shadow"] = "shadow"
    failure_mode: Literal["fail_closed", "fail_open"] | None = None  # None -> manifest default
    timeout_ms: int | None = Field(default=None, gt=0, le=30_000)
    config: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _scope(self) -> Assignment:
        if self.scope_type == "global" and self.scope_id is not None:
            raise ValueError("global assignments must not set scope_id")
        if self.scope_type != "global" and not self.scope_id:
            raise ValueError(f"{self.scope_type} assignments need scope_id")
        if self.scope_type == "agent" and "/" not in (self.scope_id or ""):
            raise ValueError("agent scope_id must be 'tenant/agent'")
        if not self.stages:
            raise ValueError("stages must not be empty")
        return self

    @property
    def tenant_id(self) -> str | None:
        """The tenant this assignment is limited to, or None for global."""
        if self.scope_type == "global" or not self.scope_id:
            return None
        return self.scope_id.split("/", 1)[0]


class SnapshotDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    environment: Environment
    assignments: list[Assignment]
    published_at: datetime | None = None
    published_by: str | None = None
    approved_by: str | None = None

    @model_validator(mode="after")
    def _unique_ids(self) -> SnapshotDoc:
        ids = [a.id for a in self.assignments]
        if len(ids) != len(set(ids)):
            raise ValueError("assignment ids must be unique")
        return self


class CatalogApiKey(BaseModel):
    """Only the SHA-256 hash of the key is published, never the key itself."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    key_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scopes: list[str] = Field(default_factory=lambda: ["guard:invoke"])
    environments: list[Environment] | None = None  # None = every environment
    expires_at: datetime | None = None
    rate_limit_per_minute: int | None = Field(default=None, ge=0)  # None = gateway default, 0 = unlimited


class CatalogAgent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    base_trust_score: int = Field(ge=0, le=100)
    allowed_tools: list[str] = Field(default_factory=lambda: ["*"])


class CatalogAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    resource_pattern: str = "*"
    base_risk_score: int = Field(ge=0, le=100)


class CatalogModifier(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["classification", "environment"]
    value: str
    delta: int = Field(ge=-100, le=100)


class CatalogTenant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    status: Literal["active", "suspended"] = "active"
    api_keys: list[CatalogApiKey] = Field(default_factory=list)
    agents: list[CatalogAgent] = Field(default_factory=list)
    actions: list[CatalogAction] = Field(default_factory=list)
    modifiers: list[CatalogModifier] = Field(default_factory=list)


class CatalogDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    tenants: list[CatalogTenant] = Field(default_factory=list)
    published_at: datetime | None = None


class EscalationStatus(BaseModel):
    """Answer to GET /v1/escalations/{id} on the gateway."""

    escalation_id: str
    status: Literal["pending", "approved", "rejected", "expired"]
    decision: Literal["escalate", "allow", "block"]
    reason: str = ""
    reviewer: str | None = None
    payload: dict[str, Any] | None = None  # the held payload, only once approved


def content_hash(doc: BaseModel, exclude: set[str] | None = None) -> str:
    """Stable hash of a document's content (used for ETags and no-op publish detection)."""
    data = doc.model_dump(mode="json", exclude=exclude or set())
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
