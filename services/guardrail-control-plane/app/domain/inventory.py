"""Agent discovery and inventory records (schema `inventory`).

Discovery turns evidence from many independent sources into one inventory and compares it with
the registry (the catalog's agent profiles):

    connector run -> observations -> entities (resolved by strong keys) -> classification
                  -> reconciliation against the registry -> state + findings
                  -> temporal edges (what talks to, holds or runs what)

No single source is trusted to be complete, so every entity keeps the sources and observations
behind it, and every edge keeps its validity window ("as of when?").
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from .records import Record, new_id, utcnow

EntityKind = Literal[
    "agent",  # an agent identity (registry, gateway traffic, cloud agent APIs)
    "workload",  # something that runs: pod, deployment, function, VM
    "endpoint",  # a network source seen only in logs (instance id or IP)
    "identity",  # a machine identity: service account, IAM role, workload identity
    "credential",  # an API key or OAuth client (metadata only, never the secret)
    "model_provider",  # api.openai.com, bedrock-runtime, a self-hosted LLM server
    "tool",  # a tool or function an agent can call
    "mcp_server",
    "datastore",  # a table, database, bucket or knowledge base
    "destination",  # an external host data is sent to
    "project",  # an account/project/namespace that groups others
]
ENTITY_KINDS: tuple[str, ...] = EntityKind.__args__  # type: ignore[attr-defined]

# Reconciliation result for anything classified as an agent (confirmed or probable).
EntityState = Literal[
    "managed",  # registered and calling through the gateway, no bypass seen
    "registered_unmanaged",  # registered, but seen calling models/tools around the gateway (or never through it)
    "shadow",  # agent-like behaviour, no registry entry
    "stale",  # registered, not observed anywhere for STALE_AFTER_DAYS
    "not_agent",  # everything else in the inventory (tools, datastores, model providers...)
]
ENTITY_STATES: tuple[str, ...] = EntityState.__args__  # type: ignore[attr-defined]
AgentLikelihood = Literal["confirmed", "probable", "none"]

FindingKind = Literal[
    "shadow_agent",
    "probable_shadow_agent",
    "unmanaged_agent",
    "stale_agent",
    "tool_definition_changed",
]
FindingStatus = Literal["open", "resolved", "accepted"]
Severity = Literal["low", "medium", "high"]
RunStatus = Literal["running", "ok", "partial", "error"]

STALE_AFTER_DAYS = 30
OBSERVATION_RETENTION_DAYS = 90


class ConnectorRecord(Record):
    """One configured source. `config` holds no secrets: credentials are named environment
    variables (`*_env` keys, prefix DISCOVERY_SECRET_) resolved when the connector runs."""

    id: str = Field(default_factory=new_id)
    tenant_id: str
    kind: str
    name: str = Field(min_length=1, max_length=100)
    config: dict[str, Any] = Field(default_factory=dict)
    environment: str | None = None  # dev | staging | production: what this source covers (coverage)
    interval_minutes: int = Field(default=60, ge=5, le=10080)
    enabled: bool = True
    created_by: str
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    last_run_at: datetime | None = None
    last_status: str | None = None
    last_error: str | None = None
    # A run in progress holds a lease so replicas (and "sync now") never run one connector twice.
    lease_owner: str | None = None
    lease_until: datetime | None = None


class SyncRunRecord(Record):
    id: str = Field(default_factory=new_id)
    tenant_id: str
    connector_id: str
    triggered_by: str
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    status: RunStatus = "running"
    observations: int = 0
    entities_created: int = 0
    entities_updated: int = 0
    edges_opened: int = 0
    edges_closed: int = 0
    findings_opened: int = 0
    findings_resolved: int = 0
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None


class ObservationRecord(Record):
    """One piece of evidence from one source. Never contains secret values or payload text."""

    id: str = Field(default_factory=new_id)
    tenant_id: str
    connector_id: str
    run_id: str
    kind: str  # e.g. gateway.agent_activity, k8s.workload, dns.model_provider_query
    source_ref: str  # where to find it in the source (pod path, ARN, log file + line)
    observed_at: datetime = Field(default_factory=utcnow)
    payload_hash: str
    attrs: dict[str, Any] = Field(default_factory=dict)
    entity_id: str | None = None  # the entity it was resolved to


class EntityRecord(Record):
    id: str = Field(default_factory=new_id)
    tenant_id: str
    kind: str
    name: str
    # Strong keys merge entities (ARN, k8s path, agent id, key id...); weak keys (IP, hostname)
    # only ever suggest a match (`probable_matches`), never merge.
    strong_keys: list[str] = Field(default_factory=list)
    weak_keys: list[str] = Field(default_factory=list)
    attrs: dict[str, Any] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)  # connector ids that reported it
    environment: str | None = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    agent_likelihood: AgentLikelihood = "none"
    reasons: list[str] = Field(default_factory=list)  # why it is (or isn't) an agent, and its state
    state: EntityState = "not_agent"
    registry_agent_id: str | None = None
    owner_guess: str | None = None
    # Model traffic attributed to this entity in the latest window: through the gateway vs direct.
    managed_volume: int = 0
    direct_volume: int = 0
    probable_matches: list[str] = Field(default_factory=list)  # entity ids sharing a weak key
    ignored_until: datetime | None = None
    ignore_reason: str | None = None
    updated_at: datetime = Field(default_factory=utcnow)

    def is_agent(self) -> bool:
        return self.agent_likelihood != "none"

    def ignored(self, now: datetime | None = None) -> bool:
        return self.ignored_until is not None and self.ignored_until > (now or utcnow())


class EdgeRecord(Record):
    """A relation valid from `valid_from` until `valid_to` (None = still valid). A changed
    relation closes the old row and opens a new one; `last_seen` is the only field refreshed."""

    id: str = Field(default_factory=new_id)
    tenant_id: str
    src: str  # entity id
    dst: str  # entity id
    # calls_model, uses_tool, reads_from, writes_to, sends_to, runs_as, holds_credential, exposes_tool,
    # member_of, collaborates_with
    kind: str
    attrs: dict[str, Any] = Field(default_factory=dict)
    source: str  # connector id
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    valid_from: datetime = Field(default_factory=utcnow)
    valid_to: datetime | None = None
    last_seen: datetime = Field(default_factory=utcnow)
    evidence_ref: str | None = None  # observation id


class FindingRecord(Record):
    id: str = Field(default_factory=new_id)
    tenant_id: str
    entity_id: str
    kind: FindingKind
    severity: Severity
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    status: FindingStatus = "open"
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    note: str = ""
