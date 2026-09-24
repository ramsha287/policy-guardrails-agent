"""Service container. Built once at startup; tests build it with fakes."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

from app.audit.writer import AuditSink
from app.config import Settings
from app.context.builder import ContextBuilder
from app.engine.pipeline import GuardrailEngine
from app.engine.registry import CompiledSnapshot, PluginRegistry
from app.engine.remote import ControlPlaneClient
from app.gateway.auth import Authenticator
from app.gateway.proxy import ChatProxy
from app.gateway.ratelimit import RateLimiter
from app.policy.opa import PolicyEngine


class SnapshotSource(Protocol):
    current: CompiledSnapshot | None
    last_error: str | None

    @property
    def version(self) -> str | None: ...


@dataclass
class Services:
    settings: Settings
    auth: Authenticator
    contexts: ContextBuilder
    policy: PolicyEngine
    engine: GuardrailEngine
    snapshots: SnapshotSource
    audit: AuditSink
    # name -> async check returning True when healthy (used by /ready)
    readiness: dict[str, Callable[[], Awaitable[bool]]] = field(default_factory=dict)
    # For /internal/simulate (compiles draft snapshots with the installed plugins)
    registry: PluginRegistry | None = None
    # CONFIG_SOURCE=control_plane only: review queue + internal token for /internal/*
    control_plane: ControlPlaneClient | None = None
    # Per-API-key rate limits (None = off)
    limiter: RateLimiter | None = None
    # PROXY_ENABLED: OpenAI-compatible chat completions with guardrails applied
    proxy: ChatProxy | None = None
