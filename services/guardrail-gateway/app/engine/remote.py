"""CONFIG_SOURCE=control_plane: keep the snapshot and catalog in sync with the control plane.

- Fetch with ETags (`If-None-Match`) every `CP_POLL_SECONDS`, and immediately when Redis
  announces a publish. A lost event only delays a change by one poll.
- Every accepted document is written to `CACHE_DIR`. At start-up, if the control plane is
  unreachable, the gateway loads the last good copies from disk and keeps serving. With neither,
  it stays not-ready and refuses requests (fail-closed).
- A heartbeat reports installed guardrail manifests, live versions and the last error, which is
  how the control plane knows a snapshot is safe to publish to this environment.
- The catalog replaces the gateway's own tables for API keys, agents, actions and modifiers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from app.context.catalog import ActionRule, AgentInfo, TenantCatalog
from app.engine.registry import PluginRegistry, SnapshotHolder
from app.engine.snapshot import parse_snapshot
from app.gateway.auth import Principal
from guardrail_sdk.documents import CatalogDoc

logger = logging.getLogger(__name__)

SNAPSHOT_CHANNEL = "guardrail:snapshot.published"
CATALOG_CHANNEL = "guardrail:catalog.published"


# ---- catalog --------------------------------------------------------------------------------


class CatalogHolder:
    """Serves API-key lookups and per-tenant scoring from the published catalog document.

    Implements both the ApiKeyStore and CatalogStore protocols used by the gateway.
    """

    def __init__(self, environment: str) -> None:
        self._env = environment
        self.doc: CatalogDoc | None = None
        self._keys: dict[str, Principal] = {}
        self._tenants: dict[str, TenantCatalog] = {}
        self.last_error: str | None = None

    @property
    def version(self) -> str | None:
        return self.doc.version if self.doc else None

    def apply(self, raw: dict[str, Any]) -> bool:
        try:
            doc = CatalogDoc.model_validate(raw)
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"catalog rejected: {exc.__class__.__name__}"
            logger.error("Catalog rejected, keeping %s", self.version)
            return False
        now = datetime.now(UTC)
        keys: dict[str, Principal] = {}
        tenants: dict[str, TenantCatalog] = {}
        for t in doc.tenants:
            if t.status != "active":
                continue  # a suspended tenant's keys stop working and nothing is scored for it
            cat = TenantCatalog(
                agents={
                    a.agent_id: AgentInfo(a.agent_id, a.base_trust_score, tuple(a.allowed_tools)) for a in t.agents
                },
                modifiers={(m.kind, m.value): m.delta for m in t.modifiers},
            )
            for r in t.actions:
                cat.actions.setdefault(r.action, []).append(ActionRule(r.action, r.resource_pattern, r.base_risk_score))
            tenants[t.id] = cat
            for k in t.api_keys:
                if k.expires_at is not None and k.expires_at <= now:
                    continue
                if k.environments is not None and self._env not in k.environments:
                    continue
                keys[k.key_hash] = Principal(k.id, t.id, k.name, frozenset(k.scopes))
        self.doc, self._keys, self._tenants, self.last_error = doc, keys, tenants, None
        logger.info("Catalog %s loaded: %d tenant(s), %d key(s)", doc.version, len(tenants), len(keys))
        return True

    async def lookup(self, key_hash: str) -> Principal | None:  # ApiKeyStore
        return self._keys.get(key_hash)

    async def load(self, tenant_id: str) -> TenantCatalog:  # CatalogStore
        return self._tenants.get(tenant_id) or TenantCatalog()


# ---- disk cache -------------------------------------------------------------------------------


class DocCache:
    def __init__(self, directory: Path, environment: str) -> None:
        self.dir = directory
        self.env = environment

    def _path(self, kind: str) -> Path:
        return self.dir / (f"snapshot-{self.env}.json" if kind == "snapshot" else "catalog.json")

    def write(self, kind: str, doc: dict[str, Any], etag: str | None) -> None:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=f".{kind}-")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"etag": etag, "document": doc}, fh)
            os.replace(tmp, self._path(kind))  # atomic swap
        except OSError as exc:
            logger.warning("Could not cache %s to %s: %s", kind, self.dir, exc)

    def read(self, kind: str) -> tuple[dict[str, Any], str | None] | None:
        try:
            data = json.loads(self._path(kind).read_text(encoding="utf-8"))
            return data["document"], data.get("etag")
        except (OSError, ValueError, KeyError):
            return None


# ---- control-plane client + sync ------------------------------------------------------------------


class ControlPlaneClient:
    def __init__(self, http: httpx.AsyncClient, base_url: str, token: str) -> None:
        self._http = http
        self._base = base_url.rstrip("/") + "/cp/v1/internal"
        self._headers = {"X-Internal-Token": token}

    async def fetch(self, path: str, etag: str | None) -> tuple[int, dict[str, Any] | None, str | None]:
        headers = dict(self._headers)
        if etag:
            headers["If-None-Match"] = etag
        resp = await self._http.get(f"{self._base}{path}", headers=headers, timeout=5.0)
        if resp.status_code == 304:
            return 304, None, etag
        if resp.status_code == 404:
            return 404, None, None
        resp.raise_for_status()
        return 200, resp.json(), resp.headers.get("etag")

    async def heartbeat(self, body: dict[str, Any]) -> None:
        resp = await self._http.post(f"{self._base}/gateways/heartbeat", json=body, headers=self._headers, timeout=5.0)
        resp.raise_for_status()

    async def create_review(self, body: dict[str, Any]) -> dict[str, Any]:
        resp = await self._http.post(f"{self._base}/reviews", json=body, headers=self._headers, timeout=5.0)
        resp.raise_for_status()
        return resp.json()

    async def review_status(self, review_id: str, tenant_id: str) -> dict[str, Any] | None:
        resp = await self._http.get(
            f"{self._base}/reviews/{review_id}", params={"tenant_id": tenant_id}, headers=self._headers, timeout=5.0
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()


class ControlPlaneSync:
    def __init__(
        self,
        client: ControlPlaneClient,
        snapshots: SnapshotHolder,
        catalog: CatalogHolder,
        registry: PluginRegistry,
        cache: DocCache,
        *,
        environment: str,
        gateway_id: str | None = None,
    ) -> None:
        self.client = client
        self.snapshots = snapshots
        self.catalog = catalog
        self.registry = registry
        self.cache = cache
        self.env = environment
        self.gateway_id = gateway_id or socket.gethostname()
        self._etags: dict[str, str | None] = {"snapshot": None, "catalog": None}
        self.last_sync_error: str | None = None
        self.control_plane_reachable = False

    async def _apply(self, kind: str, doc: dict[str, Any]) -> bool:
        if kind == "snapshot":
            try:
                parsed = parse_snapshot(doc)
            except Exception as exc:  # noqa: BLE001 - e.g. a ${VAR} this gateway lacks
                self.snapshots.last_error = f"{doc.get('version')}: {exc.__class__.__name__}: {exc}"
                logger.error("Snapshot %s rejected: %s", doc.get("version"), self.snapshots.last_error)
                return False
            return await self.snapshots.apply(parsed)
        return self.catalog.apply(doc)

    async def refresh(self, kind: str) -> bool:
        """Fetch one document; returns True if the control plane answered."""
        path = f"/environments/{self.env}/snapshot" if kind == "snapshot" else "/catalog"
        try:
            status, doc, etag = await self.client.fetch(path, self._etags[kind])
        except httpx.HTTPError as exc:
            self.last_sync_error = f"control plane unreachable ({exc.__class__.__name__})"
            self.control_plane_reachable = False
            return False
        self.control_plane_reachable = True
        self.last_sync_error = None
        if status == 200 and doc is not None and await self._apply(kind, doc):
            self._etags[kind] = etag
            self.cache.write(kind, doc, etag)
        elif status == 404 and kind == "snapshot":
            self.snapshots.last_error = f"nothing published for {self.env} yet"
        return True

    async def start(self) -> None:
        """Initial load: control plane first, disk cache as fallback."""
        for kind in ("catalog", "snapshot"):
            if not await self.refresh(kind) or self._current_version(kind) is None:
                cached = self.cache.read(kind)
                if cached is not None and await self._apply(kind, cached[0]):
                    self._etags[kind] = cached[1]
                    logger.warning("Using cached %s %s (control plane unavailable)", kind, self._current_version(kind))

    def _current_version(self, kind: str) -> str | None:
        return self.snapshots.version if kind == "snapshot" else self.catalog.version

    async def poll(self, interval_seconds: int) -> None:
        while True:
            await asyncio.sleep(interval_seconds)
            for kind in ("catalog", "snapshot"):
                await self.refresh(kind)

    async def listen(self, redis_url: str) -> None:
        """Refresh as soon as the control plane announces a publish."""
        from redis.asyncio import Redis

        while True:
            client = Redis.from_url(redis_url, decode_responses=True)
            try:
                pubsub = client.pubsub()
                await pubsub.subscribe(SNAPSHOT_CHANNEL, CATALOG_CHANNEL)
                async for message in pubsub.listen():
                    if message.get("type") != "message":
                        continue
                    if message["channel"] == CATALOG_CHANNEL:
                        await self.refresh("catalog")
                    else:
                        try:
                            env = json.loads(message["data"]).get("environment")
                        except ValueError:
                            env = None
                        if env in (None, self.env):
                            await self.refresh("snapshot")
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reconnect; polling covers the gap
                logger.warning("Control-plane event listener error (%s); retrying", exc.__class__.__name__)
                await asyncio.sleep(5)
            finally:
                await client.aclose()

    def heartbeat_body(self) -> dict[str, Any]:
        return {
            "gateway_id": self.gateway_id,
            "environment": self.env,
            "manifests": [m.model_dump(mode="json") for m in self.registry.manifests.values()],
            "snapshot_version": self.snapshots.version,
            "catalog_version": self.catalog.version,
            "last_error": "; ".join(filter(None, [self.snapshots.last_error, self.catalog.last_error])) or None,
        }

    async def heartbeat(self, interval_seconds: int) -> None:
        while True:
            try:
                await self.client.heartbeat(self.heartbeat_body())
            except httpx.HTTPError as exc:
                logger.warning("Heartbeat failed: %s", exc.__class__.__name__)
            await asyncio.sleep(interval_seconds)
