"""Plugin registry and snapshot compilation.

Compiling a snapshot instantiates one guardrail per assignment and calls setup(config).
If any assignment fails to compile, the whole snapshot is rejected and the engine keeps
serving the last good one.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path

from app.engine.snapshot import Assignment, SnapshotDoc, load_snapshot
from app.observability import SNAPSHOT_LOADED
from guardrail_sdk import Guardrail, Manifest, PluginContext, Stage
from guardrail_sdk.loader import discover_manifests, resolve_class

logger = logging.getLogger(__name__)

SCOPE_PRIORITY = {"global": 0, "tenant": 1, "agent": 2}


@dataclass(frozen=True)
class BoundGuardrail:
    assignment: Assignment
    manifest: Manifest
    guardrail: Guardrail

    @property
    def failure_mode(self) -> str:
        return self.assignment.failure_mode or self.manifest.failure_mode

    def timeout_ms(self, default_ms: int) -> int:
        if self.assignment.timeout_ms:
            return self.assignment.timeout_ms
        if self.manifest.remote is not None:
            return self.manifest.remote.timeout_ms
        return default_ms


@dataclass
class CompiledSnapshot:
    version: str
    environment: str
    bound: list[BoundGuardrail] = field(default_factory=list)

    def resolve(self, tenant_id: str, agent_id: str, stage: Stage) -> list[BoundGuardrail]:
        """Most specific scope wins per guardrail id (global < tenant < agent), then sort by order.

        A disabled assignment at a narrower scope therefore switches the guardrail off for that
        tenant or agent even when it is enabled globally.
        """
        chosen: dict[str, BoundGuardrail] = {}
        for b in self.bound:
            a = b.assignment
            if stage not in a.stages or stage not in b.manifest.stages:
                continue
            if a.scope_type == "tenant" and a.scope_id != tenant_id:
                continue
            if a.scope_type == "agent" and a.scope_id != f"{tenant_id}/{agent_id}":
                continue
            current = chosen.get(a.guardrail_id)
            if current is None or SCOPE_PRIORITY[a.scope_type] > SCOPE_PRIORITY[current.assignment.scope_type]:
                chosen[a.guardrail_id] = b
        active = [b for b in chosen.values() if b.assignment.enabled]
        return sorted(active, key=lambda b: (b.assignment.order, b.assignment.guardrail_id))

    async def close(self) -> None:
        await asyncio.gather(*(b.guardrail.close() for b in self.bound), return_exceptions=True)


class PluginRegistry:
    def __init__(self, plugin_dirs: list[Path], plugin_ctx: PluginContext) -> None:
        self._dirs = plugin_dirs
        self._ctx = plugin_ctx
        self.manifests: dict[str, Manifest] = {}

    def discover(self) -> None:
        self.manifests = {m.key: m for m in discover_manifests(self._dirs)}
        logger.info("Discovered guardrails: %s", ", ".join(sorted(self.manifests)) or "none")

    async def compile(self, doc: SnapshotDoc, environment: str) -> CompiledSnapshot:
        if doc.environment != environment:
            raise ValueError(f"snapshot is for {doc.environment!r} but gateway runs in {environment!r}")
        compiled = CompiledSnapshot(version=doc.version, environment=doc.environment)
        try:
            for a in doc.assignments:
                key = f"{a.guardrail_id}@{a.guardrail_version}"
                manifest = self.manifests.get(key)
                if manifest is None:
                    raise LookupError(f"assignment {a.id}: guardrail {key} is not installed")
                bad = [s.value for s in a.stages if s not in manifest.stages]
                if bad:
                    raise ValueError(f"assignment {a.id}: {key} does not support stage(s) {bad}")
                if a.parallel_group and not manifest.capabilities.parallel_safe:
                    raise ValueError(f"assignment {a.id}: {key} is not parallel_safe")
                guardrail = resolve_class(manifest)(manifest, self._ctx)
                await guardrail.setup(a.config)
                compiled.bound.append(BoundGuardrail(a, manifest, guardrail))
        except Exception:
            await compiled.close()
            raise
        return compiled

    async def compile_file(self, path: Path, environment: str) -> CompiledSnapshot:
        return await self.compile(load_snapshot(path), environment)


class SnapshotHolder:
    """Holds the live snapshot and swaps it atomically.

    Sources: a file (CONFIG_SOURCE=file, reloaded when it changes) or documents pushed in by the
    control-plane sync (`apply`). A snapshot that fails to compile is rejected and the last good
    one keeps serving; the error is reported on /ready and to the control plane.
    """

    def __init__(self, registry: PluginRegistry, path: Path | None, environment: str) -> None:
        self._registry = registry
        self._path = path
        self._env = environment
        self._mtime: float | None = None
        self.current: CompiledSnapshot | None = None
        self.last_error: str | None = None

    async def apply(self, doc: SnapshotDoc) -> bool:
        if self.current is not None and self.current.version == doc.version:
            return True
        try:
            new = await self._registry.compile(doc, self._env)
        except Exception as exc:  # noqa: BLE001 - keep serving the last good snapshot
            self.last_error = f"{doc.version}: {exc.__class__.__name__}: {exc}"
            logger.error("Snapshot rejected, keeping %s: %s", self.version, self.last_error)
            return False
        old, self.current, self.last_error = self.current, new, None
        SNAPSHOT_LOADED.set(1)
        logger.info("Snapshot %s loaded with %d assignment(s)", new.version, len(new.bound))
        if old is not None:
            # Let in-flight requests on the old snapshot finish before closing its clients.
            asyncio.get_running_loop().call_later(30, lambda: asyncio.ensure_future(old.close()))
        return True

    async def load(self) -> bool:
        assert self._path is not None, "file source needs a path"
        try:
            mtime = self._path.stat().st_mtime
            doc = load_snapshot(self._path)
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"{exc.__class__.__name__}: {exc}"
            logger.error("Snapshot %s unreadable, keeping %s: %s", self._path, self.version, self.last_error)
            return False
        self._mtime = mtime
        return await self.apply(doc)

    @property
    def version(self) -> str | None:
        return self.current.version if self.current else None

    async def reload_if_changed(self) -> None:
        if self._path is None:
            return
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            return
        if mtime != self._mtime:
            await self.load()

    async def watch(self, interval_seconds: int) -> None:
        while True:
            await asyncio.sleep(interval_seconds)
            await self.reload_if_changed()

    async def close(self) -> None:
        if self.current:
            await self.current.close()
