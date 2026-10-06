"""Compile the working set into a publishable SnapshotDoc, and the catalog into a CatalogDoc.

Validation mirrors what the gateway does when it loads a snapshot, so a bad snapshot is
rejected here, before any gateway sees it:
- the guardrail version is registered and not deprecated;
- every assignment stage is supported by that version;
- the config validates against the version's `config_schema` (JSON Schema);
- `parallel_group` is only used with `parallel_safe` guardrails;
- the version is installed on the environment's live gateways (unless `force`).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from guardrail_sdk.documents import (
    Assignment,
    CatalogAction,
    CatalogAgent,
    CatalogApiKey,
    CatalogDoc,
    CatalogModifier,
    CatalogTenant,
    SnapshotDoc,
    content_hash,
)
from guardrail_sdk.manifest import Manifest

from .records import (
    ActionRecord,
    AgentRecord,
    ApiKeyRecord,
    GatewayRecord,
    GuardrailVersionRecord,
    ModifierRecord,
    TenantRecord,
    utcnow,
)


@dataclass
class CompileResult:
    document: SnapshotDoc | None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.document is not None and not self.errors


def snapshot_version(environment: str, doc: SnapshotDoc, sequence: int) -> str:
    """e.g. production-00012-3fa2c1d0: per-environment sequence + content hash.

    The sequence keeps versions unique even when a rollback republishes identical content.
    """
    digest = content_hash(doc, {"version", "published_at", "published_by", "approved_by"})[:8]
    return f"{environment}-{sequence:05d}-{digest}"


def validate_config(manifest: Manifest, config: dict) -> list[str]:
    try:
        validator = Draft202012Validator(manifest.config_schema)
    except SchemaError as exc:
        return [f"{manifest.key} has an invalid config_schema: {exc.message}"]
    return [
        f"config{''.join(f'[{p!r}]' for p in e.absolute_path)}: {e.message}"
        for e in sorted(validator.iter_errors(config), key=lambda e: list(e.absolute_path))
    ]


def compile_snapshot(
    environment: str,
    assignments: Iterable[Assignment],
    versions: dict[str, GuardrailVersionRecord],
    gateways: Iterable[GatewayRecord] = (),
    *,
    force: bool = False,
    stale_after_seconds: int = 300,
) -> CompileResult:
    result = CompileResult(document=None)
    live = [g for g in gateways if (utcnow() - g.last_seen).total_seconds() <= stale_after_seconds]
    ordered = sorted(assignments, key=lambda a: (a.order, a.id))
    for a in ordered:
        key = f"{a.guardrail_id}@{a.guardrail_version}"
        rec = versions.get(key)
        if rec is None:
            result.errors.append(f"{a.id}: guardrail {key} is not registered")
            continue
        if rec.status == "deprecated":
            (result.warnings if force else result.errors).append(f"{a.id}: {key} is deprecated")
        manifest = Manifest.model_validate(rec.manifest)
        unsupported = [s.value for s in a.stages if s not in manifest.stages]
        if unsupported:
            result.errors.append(f"{a.id}: {key} does not support stage(s) {unsupported}")
        if a.parallel_group and not manifest.capabilities.parallel_safe:
            result.errors.append(f"{a.id}: {key} is not parallel_safe but has parallel_group")
        result.errors.extend(f"{a.id}: {msg}" for msg in validate_config(manifest, a.config))
        missing_on = [g.gateway_id for g in live if key not in g.installed]
        if missing_on:
            msg = f"{a.id}: {key} is not installed on gateway(s) {', '.join(sorted(missing_on))}"
            (result.warnings if force else result.errors).append(msg)
    if not live:
        result.warnings.append(f"no live gateways reported for {environment}; installation not verified")
    if result.errors:
        return result
    result.document = SnapshotDoc(version="draft", environment=environment, assignments=ordered)  # type: ignore[arg-type]
    return result


@dataclass
class InventoryFlags:
    """What the inventory tells gateways about one tenant (see CatalogService._inventory_flags)."""

    agent_findings: dict[str, list[str]] = field(default_factory=dict)  # agent_id -> open finding kinds
    flagged_tools: list[str] = field(default_factory=list)  # tools with an unapproved definition change


def build_catalog(
    tenants: Iterable[TenantRecord],
    keys: Iterable[ApiKeyRecord],
    agents: Iterable[AgentRecord],
    actions: Iterable[ActionRecord],
    modifiers: Iterable[ModifierRecord],
    inventory: dict[str, InventoryFlags] | None = None,
) -> CatalogDoc:
    now = utcnow()
    inventory = inventory or {}
    by_tenant: dict[str, CatalogTenant] = {
        t.id: CatalogTenant(id=t.id, name=t.name, status=t.status, advisor_data_classes=t.advisor_data_classes)
        for t in sorted(tenants, key=lambda t: t.id)
    }
    for k in sorted(keys, key=lambda k: k.id):
        if k.is_active and (k.expires_at is None or k.expires_at > now) and k.tenant_id in by_tenant:
            by_tenant[k.tenant_id].api_keys.append(
                CatalogApiKey(
                    id=k.id,
                    name=k.name,
                    key_hash=k.key_hash,
                    scopes=k.scopes,
                    environments=k.environments,
                    expires_at=k.expires_at,
                    rate_limit_per_minute=k.rate_limit_per_minute,
                    agent_id=k.agent_id,
                )
            )
    for a in sorted(agents, key=lambda a: (a.tenant_id, a.agent_id)):
        if a.tenant_id in by_tenant:
            flags = inventory.get(a.tenant_id)
            by_tenant[a.tenant_id].agents.append(
                CatalogAgent(
                    agent_id=a.agent_id,
                    base_trust_score=a.base_trust_score,
                    allowed_tools=a.allowed_tools,
                    open_findings=sorted(set(flags.agent_findings.get(a.agent_id, []))) if flags else [],
                )
            )
    for r in sorted(actions, key=lambda r: (r.tenant_id, r.action, r.resource_pattern)):
        if r.tenant_id in by_tenant:
            by_tenant[r.tenant_id].actions.append(
                CatalogAction(action=r.action, resource_pattern=r.resource_pattern, base_risk_score=r.base_risk_score)
            )
    for m in sorted(modifiers, key=lambda m: (m.tenant_id, m.kind, m.value)):
        if m.tenant_id in by_tenant:
            by_tenant[m.tenant_id].modifiers.append(CatalogModifier(kind=m.kind, value=m.value, delta=m.delta))
    for tid, flags in inventory.items():
        if tid in by_tenant and flags.flagged_tools:
            by_tenant[tid].flagged_tools = sorted(set(flags.flagged_tools))
    doc = CatalogDoc(version="pending", tenants=list(by_tenant.values()))
    digest = content_hash(doc, {"version", "published_at"})
    return doc.model_copy(update={"version": catalog_version(now, digest)})


def catalog_version(published_at: datetime, digest: str) -> str:
    """e.g. catalog-20261002102521872653-f2d3c5d0: publish time (to the microsecond) + content hash.

    The hash alone repeats when content returns to an earlier state (bind then unbind a key), so
    the publisher keeps publish times strictly increasing to keep versions unique.
    """
    return f"catalog-{published_at.strftime('%Y%m%d%H%M%S%f')}-{digest[:8]}"


def catalog_content_hash(doc: CatalogDoc) -> str:
    return content_hash(doc, {"version", "published_at"})


def etag(doc_hash: str) -> str:
    return f'"{doc_hash[:32]}"'
