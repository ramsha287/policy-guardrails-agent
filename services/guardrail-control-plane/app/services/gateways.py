"""Gateway fleet: gateways report their installed guardrail manifests and live versions."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from ..domain.rbac import Permission, Principal
from ..domain.records import GatewayRecord, utcnow
from ..errors import ValidationFailed
from .context import Ctx
from .registry import RegistryService

logger = logging.getLogger(__name__)


def _changes_catalog_audience(previous: GatewayRecord | None, current: GatewayRecord) -> bool:
    from .catalog import BINDING_GATEWAY_WINDOW_MINUTES

    if previous is None or previous.capabilities != current.capabilities:
        return True
    return (current.last_seen - previous.last_seen) > timedelta(minutes=BINDING_GATEWAY_WINDOW_MINUTES)


class GatewayService:
    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.registry = RegistryService(ctx)

    async def heartbeat(
        self,
        *,
        gateway_id: str,
        environment: str,
        manifests: list[dict[str, Any]],
        snapshot_version: str | None,
        catalog_version: str | None,
        last_error: str | None,
        capabilities: list[str] | None = None,
    ) -> GatewayRecord:
        installed = []
        problems = []
        for raw in manifests:
            try:
                rec = await self.registry.register(None, raw, source="gateway")
                installed.append(f"{rec.guardrail_id}@{rec.version}")
            except ValidationFailed as exc:
                problems.append(f"{raw.get('id')}@{raw.get('version')}: {exc}")
            except Exception as exc:  # noqa: BLE001 - e.g. a conflicting manifest; report, keep going
                problems.append(f"{raw.get('id')}@{raw.get('version')}: {exc}")
        record = GatewayRecord(
            gateway_id=gateway_id,
            environment=environment,  # type: ignore[arg-type]
            snapshot_version=snapshot_version,
            catalog_version=catalog_version,
            last_error="; ".join(filter(None, [last_error, *problems])) or None,
            installed=sorted(installed),
            last_seen=utcnow(),
            capabilities=sorted(set(capabilities or [])),
        )
        previous = next((g for g in await self.store.list_gateways() if g.gateway_id == gateway_id), None)
        await self.store.put_gateway(record)
        if _changes_catalog_audience(previous, record):
            # The catalog leaves out fields that live gateways can't read (catalog._inventory_flags).
            # A gateway joining, returning or upgrading changes who is live: rebuild it now, so an
            # old gateway isn't stuck with a catalog it rejects, and an upgrade gets the fields.
            from .catalog import CatalogService

            try:
                await CatalogService(self.ctx).publish()
            except Exception:  # noqa: BLE001 - the heartbeat stands; the next publish catches up
                logger.warning("catalog republish after a gateway heartbeat failed", exc_info=True)
        return record

    async def list(self, p: Principal, environment: str | None) -> list[tuple[GatewayRecord, bool]]:
        """(gateway, is_live)."""
        p.require(Permission.READ, p.tenant_id)
        now = utcnow()
        stale = self.ctx.policy.gateway_stale_seconds
        return [(g, (now - g.last_seen).total_seconds() <= stale) for g in await self.store.list_gateways(environment)]
