"""The Guardrail base class every plugin implements, plus the services the engine injects."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ConfigDict

from .manifest import Manifest
from .models import GuardrailResult, Payload, SecurityContext, Stage


class StateStore(Protocol):
    """Tenant-scoped key/value store (Redis in production). For stateful guardrails only."""

    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None: ...
    async def incr(self, key: str, ttl_seconds: int | None = None) -> int: ...


class SecretReader(Protocol):
    def get(self, ref: str) -> str | None: ...


class PluginContext:
    """Everything a plugin may use. Plugins must not create their own globals (requirement B5)."""

    def __init__(
        self,
        *,
        http: httpx.AsyncClient,
        secrets: SecretReader,
        state: StateStore | None = None,
        logger: logging.Logger | None = None,
        environment: str = "dev",
    ) -> None:
        self.http = http
        self.secrets = secrets
        self.state = state
        self.logger = logger or logging.getLogger("guardrail.plugin")
        self.environment = environment


class EmptyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Guardrail(ABC):
    """Base class. Subclasses set `config_model` and implement `evaluate`.

    Rules (see plugin requirements B1-B7):
    - never mutate `context`; return a new Payload for MODIFY;
    - be deterministic for the same input, config and version;
    - never log or return raw sensitive values;
    - do blocking/CPU work off the event loop.
    """

    config_model: type[BaseModel] = EmptyConfig

    def __init__(self, manifest: Manifest, plugin_ctx: PluginContext) -> None:
        self.manifest = manifest
        self.ctx = plugin_ctx
        self.config: BaseModel = EmptyConfig()

    @property
    def id(self) -> str:
        return self.manifest.id

    @property
    def version(self) -> str:
        return self.manifest.version

    @property
    def stages(self) -> set[Stage]:
        return set(self.manifest.stages)

    async def setup(self, config: dict[str, Any]) -> None:
        """Validate config and prepare resources. Must fail fast on bad config (B6)."""
        self.config = self.config_model.model_validate(config)

    @abstractmethod
    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        """Inspect `payload` for `context` and return a decision."""

    async def health(self) -> bool:
        return True

    async def close(self) -> None:
        return None
