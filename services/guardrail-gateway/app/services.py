"""Service container. Built once at startup; tests build it with fakes."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

from app.audit.writer import AuditSink
from app.config import Settings
from app.context.builder import ContextBuilder
from app.engine.pipeline import GuardrailEngine
from app.engine.registry import CompiledSnapshot
from app.gateway.auth import Authenticator
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
