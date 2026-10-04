"""What connectors produce, and the contract every connector implements.

A connector reads ONE source with read-only access and yields `Observation`s. Each observation
already carries its normalized facts (the connector knows its source best):

    EntityFact  something that exists (a workload, an identity, a tool...), with strong keys that
                identify it across sources and the classification signals the source supports
    EdgeFact    a relation between two facts of the same observation (by their local `ref`)

The pipeline (app/discovery/pipeline.py) resolves facts to inventory entities, so connectors never
touch the store, and the store never sees a credential.

Classification signals (app/discovery/classify.py turns them into "agent or not"):

    registered          the registry has this agent (reconciler only)
    gateway_client      seen at our gateway as an agent_id, or configured to use it (SDK/proxy env)
    agent_runtime       a managed agent runtime says so (Bedrock agent, AgentCore runtime, kagent Agent)
    agent_framework     runs an agent framework (LangGraph, CrewAI, AutoGen, Agents SDK...)
    mcp_client          configured to call MCP servers
    calls_model         calls a model API (directly or through the gateway)
    direct_model_access calls a model provider without going through the gateway (bypass)
    uses_tools          calls tools or touches data stores
    llm_server          serves a model (vLLM, Ollama, TGI): infrastructure, not an agent
    human_identity      a person's identity or key: not an agent
"""

from __future__ import annotations

import socket
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Protocol

import httpx
from pydantic import BaseModel, ConfigDict

SIGNALS = frozenset(
    {
        "registered",
        "gateway_client",
        "agent_runtime",
        "agent_framework",
        "mcp_client",
        "calls_model",
        "direct_model_access",
        "uses_tools",
        "llm_server",
        "human_identity",
    }
)

Fetch = Callable[[str, dict[str, Any]], Awaitable[list[dict[str, Any]]]]
Resolver = Callable[[str], list[str]]  # host -> IP addresses


def default_resolver(host: str) -> list[str]:
    return sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None)})


@dataclass
class EntityFact:
    ref: str  # local handle inside one observation ("self", "role", "provider"...)
    kind: str
    name: str
    strong_keys: list[str]
    weak_keys: list[str] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)
    signals: set[str] = field(default_factory=set)
    environment: str | None = None
    owner: str | None = None
    managed_volume: int = 0  # model/tool requests seen through the gateway in the window
    direct_volume: int = 0  # model calls (or lookups) seen going around it


@dataclass
class EdgeFact:
    src: str  # EntityFact.ref
    dst: str
    kind: str
    attrs: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0


@dataclass
class Observation:
    kind: str
    source_ref: str
    entities: list[EntityFact]
    edges: list[EdgeFact] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)  # stored as evidence: names and counts, never secrets
    observed_at: datetime | None = None


class ConnectorError(Exception):
    """A configuration or source problem the operator must fix (shown on the run)."""


@dataclass
class CollectContext:
    tenant_id: str
    connector_id: str
    environment: str | None
    http: httpx.AsyncClient
    now: datetime
    since: datetime | None  # last successful run
    secrets: Callable[[str], str]  # resolves a DISCOVERY_SECRET_* name (app/discovery/safety.py)
    check_url: Callable[[str], Awaitable[None]]  # raises ConnectorError for forbidden destinations
    audit_fetch: Fetch | None = None  # SQL over the gateway's audit schema (gateway connector)
    clients: Mapping[str, Any] = field(default_factory=dict)  # injected SDK clients (tests, AWS)
    warnings: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        if len(self.warnings) < 50:
            self.warnings.append(message[:500])


class ConnectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Connector(Protocol):
    kind: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str]
    # True: every run lists everything the source has, so what is missing was removed (its edges
    # close). False: the source reports activity in a window (logs), so edges age out instead.
    full_snapshot: ClassVar[bool]
    Config: ClassVar[type[ConnectorConfig]]

    def collect(self, config: Any, ctx: CollectContext) -> AsyncIterator[Observation]: ...
