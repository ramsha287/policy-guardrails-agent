"""Guardrail manifest (`guardrail.yaml`): what every plugin must declare to be registered."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import SDK_VERSION, Decision, Stage

_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class Capabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    emits_modify: bool = False
    needs_state: bool = False
    needs_raw_payload: bool = False
    parallel_safe: bool = False
    supports_batch: bool = False
    max_payload_kb: int = 1024


class RemoteSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint: str
    auth: Literal["api_key", "mtls", "none"] = "api_key"
    api_key_ref: str | None = None  # e.g. env://AI_GATEWAY_API_KEY
    timeout_ms: int = Field(default=800, gt=0, le=30_000)


class Manifest(BaseModel):
    """Plugin requirement section A. Unknown keys are rejected so typos surface early."""

    model_config = ConfigDict(extra="forbid")

    id: str
    version: str
    kind: Literal["local", "remote", "model"]
    stages: list[Stage]
    description: str
    owner: str
    data_handling: str
    config_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    failure_mode: Literal["fail_closed", "fail_open"] = "fail_closed"
    decisions_emitted: list[Decision]
    sdk_version: str = ">=1.0,<2.0"
    latency_budget_ms: int = Field(default=300, gt=0)
    capabilities: Capabilities = Field(default_factory=Capabilities)
    # `local`: import path of the Guardrail subclass. `remote`/`model`: optional adapter class;
    # without one the generic HTTP protocol (POST /evaluate) is used.
    entrypoint: str | None = None
    remote: RemoteSpec | None = None

    @field_validator("id")
    @classmethod
    def _kebab(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("id must be kebab-case, e.g. ai-gateway-pii")
        return v

    @field_validator("version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not _SEMVER_RE.match(v):
            raise ValueError("version must be semver MAJOR.MINOR.PATCH")
        return v

    @field_validator("stages")
    @classmethod
    def _stages_not_empty(cls, v: list[Stage]) -> list[Stage]:
        if not v:
            raise ValueError("stages must list at least one stage")
        return v

    @model_validator(mode="after")
    def _kind_rules(self) -> Manifest:
        if self.kind == "local" and not self.entrypoint:
            raise ValueError("local guardrails must set `entrypoint` (module:Class)")
        if self.kind in ("remote", "model") and self.remote is None:
            raise ValueError("remote and model guardrails must set `remote` (endpoint, auth, timeout_ms)")
        if Decision.MODIFY in self.decisions_emitted and not self.capabilities.emits_modify:
            raise ValueError("decisions_emitted includes modify, so capabilities.emits_modify must be true")
        if self.capabilities.parallel_safe and self.capabilities.emits_modify:
            raise ValueError("a guardrail that emits MODIFY cannot be parallel_safe")
        if not sdk_version_satisfies(SDK_VERSION, self.sdk_version):
            raise ValueError(f"sdk_version {self.sdk_version!r} does not accept installed SDK {SDK_VERSION}")
        return self

    @property
    def key(self) -> str:
        return f"{self.id}@{self.version}"

    @classmethod
    def from_yaml(cls, path: str | Path) -> Manifest:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)


def _parse(v: str) -> tuple[int, ...]:
    parts = [int(p) for p in v.split(".")]
    return tuple(parts + [0] * (3 - len(parts)))


def sdk_version_satisfies(version: str, spec: str) -> bool:
    """Minimal PEP 440-style range check supporting >=, >, <=, <, == joined by commas."""
    current = _parse(version)
    for clause in (c.strip() for c in spec.split(",") if c.strip()):
        m = re.match(r"^(>=|<=|==|>|<)\s*([\d.]+)$", clause)
        if not m:
            raise ValueError(f"unsupported version clause: {clause!r}")
        op, target = m.group(1), _parse(m.group(2))
        ok = {
            ">=": current >= target,
            "<=": current <= target,
            ">": current > target,
            "<": current < target,
            "==": current == target,
        }[op]
        if not ok:
            return False
    return True
