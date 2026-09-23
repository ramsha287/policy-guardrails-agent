"""Turn a manifest into a Guardrail class, and discover installed plugins."""

from __future__ import annotations

import importlib
from importlib.metadata import entry_points
from pathlib import Path

from .guardrail import Guardrail
from .manifest import Manifest
from .remote import RemoteGuardrail

ENTRY_POINT_GROUP = "guardrails.plugins"


def import_object(path: str) -> object:
    module_name, _, attr = path.partition(":")
    if not module_name or not attr:
        raise ValueError(f"entrypoint must look like 'package.module:ClassName', got {path!r}")
    module = importlib.import_module(module_name)
    return getattr(module, attr)


def resolve_class(manifest: Manifest) -> type[Guardrail]:
    if manifest.entrypoint:
        cls = import_object(manifest.entrypoint)
        if not (isinstance(cls, type) and issubclass(cls, Guardrail)):
            raise TypeError(f"{manifest.entrypoint} is not a Guardrail subclass")
        return cls
    if manifest.kind in ("remote", "model"):
        return RemoteGuardrail
    raise ValueError(f"cannot resolve a class for {manifest.key}")


def discover_manifests(extra_dirs: list[Path] | None = None) -> list[Manifest]:
    """Manifests from installed packages (entry point group `guardrails.plugins`) and plugin dirs.

    An entry point must resolve to a callable returning the path of its guardrail.yaml.
    """
    found: dict[str, Manifest] = {}
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        path = ep.load()()
        m = Manifest.from_yaml(path)
        found[m.key] = m
    for d in extra_dirs or []:
        for path in sorted(Path(d).glob("*/guardrail*.yaml")):
            m = Manifest.from_yaml(path)
            found[m.key] = m
    return list(found.values())
