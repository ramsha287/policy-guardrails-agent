"""Guardrail registry: which guardrail versions exist and what they declare.

Versions arrive two ways: gateways report the manifests they have installed at start-up
(`source=gateway`), or an admin registers one through the API (e.g. a remote guardrail
running elsewhere). Versions are immutable; a new manifest for an existing id@version is
rejected unless it is identical. Deprecating keeps old snapshots valid but blocks new use.
"""

from __future__ import annotations

from typing import Any

import yaml
from pydantic import ValidationError

from guardrail_sdk.manifest import Manifest

from ..domain.rbac import Permission, Principal
from ..domain.records import GuardrailVersionRecord
from ..errors import NotFound, ValidationFailed
from ..store.base import Conflict
from .context import Ctx


def load_manifest_yaml(text: str) -> dict[str, Any]:
    """guardrail.yaml text -> dict (safe loader only)."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        raise ValidationFailed("manifest is not valid YAML", [f"YAML error{where}"]) from exc
    if not isinstance(data, dict):
        raise ValidationFailed("manifest must be a YAML mapping", ["top level is not a mapping"])
    return data


def parse_manifest(raw: dict[str, Any]) -> Manifest:
    try:
        return Manifest.model_validate(raw)
    except ValidationError as exc:
        raise ValidationFailed("invalid manifest", [e["msg"] for e in exc.errors()]) from exc


class RegistryService:
    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx
        self.store = ctx.store

    async def register(
        self,
        p: Principal | None,
        raw_manifest: dict[str, Any],
        *,
        source: str = "api",
        conformance_report: dict[str, Any] | None = None,
    ) -> GuardrailVersionRecord:
        if p is not None:
            p.require(Permission.REGISTRY_WRITE)
        manifest = parse_manifest(raw_manifest)
        if conformance_report is not None and not conformance_report.get("passed", False):
            raise ValidationFailed(f"{manifest.key} failed conformance", ["conformance report has passed=false"])
        canonical = manifest.model_dump(mode="json")
        existing = await self.store.get_version(manifest.id, manifest.version)
        if existing is not None:
            if existing.manifest != canonical:
                raise Conflict(f"{manifest.key} is already registered with a different manifest; bump the version")
            return existing
        record = GuardrailVersionRecord(
            guardrail_id=manifest.id,
            version=manifest.version,
            manifest=canonical,
            source=source,  # type: ignore[arg-type]
            conformance_report=conformance_report,
        )
        await self.store.put_version(record)
        await self.ctx.log("guardrail_version", manifest.key, "register", p.actor if p else f"gateway ({source})")
        return record

    async def deprecate(self, p: Principal, guardrail_id: str, version: str) -> GuardrailVersionRecord:
        p.require(Permission.REGISTRY_WRITE)
        rec = await self.store.get_version(guardrail_id, version)
        if rec is None:
            raise NotFound(f"{guardrail_id}@{version} not found")
        rec = rec.model_copy(update={"status": "deprecated"})
        await self.store.put_version(rec)
        await self.ctx.log("guardrail_version", f"{guardrail_id}@{version}", "deprecate", p.actor)
        return rec

    async def list(self, p: Principal, guardrail_id: str | None = None) -> list[GuardrailVersionRecord]:
        p.require(Permission.READ, p.tenant_id)
        return await self.store.list_versions(guardrail_id)

    async def versions_by_key(self) -> dict[str, GuardrailVersionRecord]:
        return {f"{v.guardrail_id}@{v.version}": v for v in await self.store.list_versions()}
