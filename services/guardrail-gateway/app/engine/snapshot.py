"""Snapshot = the compiled guardrail pipeline for one environment.

CONFIG_SOURCE=file: a JSON file (config/snapshots/<env>.json), hot-reloaded on change.
CONFIG_SOURCE=control_plane: the control plane publishes the same document (see
app/engine/remote.py), and the gateway keeps the last good copy on disk.
`${VAR}` / `${VAR:-default}` in string values are expanded from the environment, so
secrets and IDs never live in the file.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

# The documents are part of the SDK contract so the control plane and gateway share them.
from guardrail_sdk.documents import Assignment, SnapshotDoc

__all__ = ["Assignment", "SnapshotDoc", "expand_env", "load_snapshot", "parse_snapshot"]

_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


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


def parse_snapshot(raw: dict[str, Any]) -> SnapshotDoc:
    """Validate a snapshot document after expanding ${VAR} placeholders."""
    return SnapshotDoc.model_validate(expand_env(raw))


def load_snapshot(path: Path) -> SnapshotDoc:
    return parse_snapshot(json.loads(path.read_text(encoding="utf-8")))
