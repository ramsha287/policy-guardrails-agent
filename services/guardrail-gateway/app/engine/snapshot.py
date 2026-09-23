"""Snapshot = the compiled guardrail pipeline for one environment.

Phase 1-3: a JSON file (config/snapshots/<env>.json), hot-reloaded on change.
Phase 4: the control plane publishes the same document and the engine fetches it.
`${VAR}` / `${VAR:-default}` in string values are expanded from the environment, so
secrets and IDs never live in the file.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from guardrail_sdk import Stage

_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


class Assignment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
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
        return self


class SnapshotDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    environment: Literal["dev", "staging", "production"]
    assignments: list[Assignment]

    @model_validator(mode="after")
    def _unique_ids(self) -> SnapshotDoc:
        ids = [a.id for a in self.assignments]
        if len(ids) != len(set(ids)):
            raise ValueError("assignment ids must be unique")
        return self


def expand_env(value: Any) -> Any:
    if isinstance(value, str):

        def repl(m: re.Match[str]) -> str:
            name, default = m.group(1), m.group(2)
            if name in os.environ:
                return os.environ[name]
            if default is not None:
                return default
            raise KeyError(f"snapshot references ${{{name}}} but it is not set")

        return _VAR_RE.sub(repl, value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


def load_snapshot(path: Path) -> SnapshotDoc:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return SnapshotDoc.model_validate(expand_env(raw))
