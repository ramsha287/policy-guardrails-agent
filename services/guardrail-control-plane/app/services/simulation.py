"""Dry runs: send a request through a draft (the working set) or the live snapshot on a real gateway.

The gateway compiles the snapshot with its installed plugins and runs OPA, without enforcing,
auditing or filing reviews. Each environment can have its own gateway (`GATEWAY_URLS`). If an
environment has none, the default gateway (`GATEWAY_URL`) simulates it *as* that environment:
scores and the OPA input use the target environment, while plugins use that gateway's endpoints.
"""

from __future__ import annotations

from typing import Any, Literal

import httpx

from guardrail_sdk.api import GuardRequest
from guardrail_sdk.documents import SnapshotDoc
from guardrail_sdk.models import Stage

from ..domain.compiler import compile_snapshot
from ..domain.rbac import Permission, Principal
from ..errors import NotFound, ValidationFailed
from .catalog import CatalogService
from .context import Ctx
from .registry import RegistryService


class SimulationUnavailable(Exception):
    """No gateway is configured for simulation, or the gateway could not be reached (HTTP 503/502)."""

    def __init__(self, message: str, status: int = 503) -> None:
        super().__init__(message)
        self.status = status


class SimulationService:
    def __init__(
        self,
        ctx: Ctx,
        registry: RegistryService,
        catalog: CatalogService,
        http: httpx.AsyncClient,
        internal_token: str,
        gateway_urls: dict[str, str] | None = None,
        default_gateway_url: str | None = None,
    ) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.registry = registry
        self.catalog = catalog
        self.http = http
        self.internal_token = internal_token
        self.gateway_urls = {k: v.rstrip("/") for k, v in (gateway_urls or {}).items()}
        self.default_gateway_url = default_gateway_url.rstrip("/") if default_gateway_url else None

    def gateway_for(self, environment: str) -> str | None:
        return self.gateway_urls.get(environment) or self.default_gateway_url

    async def run(
        self,
        p: Principal,
        *,
        environment: str,
        source: Literal["working", "current"],
        tenant_id: str,
        stage: Stage,
        request: GuardRequest,
    ) -> dict[str, Any]:
        p.require(Permission.READ, tenant_id)
        if await self.store.get_tenant(tenant_id) is None:
            raise NotFound(f"tenant {tenant_id} not found")
        url = self.gateway_for(environment)
        if url is None:
            raise SimulationUnavailable("no gateway is configured for simulation (set GATEWAY_URL or GATEWAY_URLS)")

        warnings: list[str] = []
        if source == "current":
            live = await self.store.current_snapshot(environment)
            if live is None:
                raise NotFound(f"nothing published in {environment} yet")
            doc = SnapshotDoc.model_validate(live.document)
        else:
            working = [r.assignment for r in await self.store.list_assignments(environment)]
            result = compile_snapshot(environment, working, await self.registry.versions_by_key(), force=True)
            if result.document is None:
                raise ValidationFailed("working set is invalid", result.errors, result.warnings)
            doc = result.document
            warnings.extend(result.warnings)

        catalog = await self.catalog.current_document()
        try:
            resp = await self.http.post(
                f"{url}/internal/simulate",
                json={
                    "snapshot": doc.model_dump(mode="json"),
                    "catalog": catalog[0] if catalog else None,
                    "tenant_id": tenant_id,
                    "stage": stage.value,
                    "request": request.model_dump(mode="json"),
                },
                headers={"X-Internal-Token": self.internal_token},
            )
        except httpx.HTTPError as exc:
            raise SimulationUnavailable(f"gateway at {url} is unreachable ({exc.__class__.__name__})", 502) from exc

        body = _json(resp)
        if resp.status_code == 422:
            # The gateway explains why (e.g. a guardrail version it does not have installed).
            raise ValidationFailed(f"gateway rejected the simulation: {body.get('error', resp.text[:300])}")
        if resp.status_code != 200:
            detail = body.get("error") or resp.text[:300]
            raise SimulationUnavailable(f"gateway simulation failed: HTTP {resp.status_code}: {detail}", 502)

        if body.get("simulated_on") and body.get("simulated_on") != environment:
            warnings.append(
                f"simulated on a {body['simulated_on']} gateway: plugins used that gateway's endpoints and secrets"
            )
        return {"source": source, "snapshot": doc.version, "warnings": warnings, "result": body}


def _json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}
