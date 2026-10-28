"""Memory Firewall: the console's view of services/memory-firewall.

The control plane relays to the service with its API key (MEMORY_FIREWALL_API_KEY), so the console
keeps talking to one origin and never holds that key. The service is platform-wide (one signing key,
one event log for every tenant), so everything except the status needs a platform key:

    status        read (any key)                   reachable?, library version, signing key, counters
    events        read, platform                   the newest event-log entries (ids and reasons only)
    scan          catalog:write, platform          heuristic scan, changes nothing
    inspect       catalog:write, platform          writer gate + source trust: records provenance, logs events
    self-test     catalog:write, platform          the five checkpoint attacks against GuardedSaver

Inspect and self-test are recorded in the change log (who, how many items, the outcome); memory
text never is.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from ..domain.rbac import Permission, Principal
from .context import Ctx
from .simulation import SimulationUnavailable


class MemoryFirewallService:
    def __init__(
        self,
        ctx: Ctx,
        http: httpx.AsyncClient,
        *,
        url: str,
        api_key: str | None,
        selftest_timeout: float = 150.0,
    ) -> None:
        self.ctx = ctx
        self.http = http
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.selftest_timeout = selftest_timeout

    async def _call(self, method: str, path: str, body: dict[str, Any] | None = None, **kw: Any) -> dict[str, Any]:
        headers = {"X-API-Key": self.api_key} if self.api_key else {}
        try:
            resp = await self.http.request(method, f"{self.url}{path}", json=body, headers=headers, **kw)
        except httpx.TimeoutException as exc:
            raise SimulationUnavailable("memory-firewall did not answer in time", 504) from exc
        except httpx.HTTPError as exc:
            raise SimulationUnavailable(f"memory-firewall is unreachable ({exc.__class__.__name__})", 502) from exc
        try:
            data = resp.json()
        except ValueError:
            data = {}
        if resp.status_code == 401:
            raise SimulationUnavailable(
                "memory-firewall refused the control plane's key (MEMORY_FIREWALL_API_KEY)", 502
            )
        if resp.status_code >= 400:
            msg = data.get("error") if isinstance(data, dict) else None
            status = resp.status_code if resp.status_code in (413, 422) else 502
            raise SimulationUnavailable(f"memory-firewall: {msg or f'HTTP {resp.status_code}'}", status)
        if not isinstance(data, dict):
            raise SimulationUnavailable("memory-firewall returned an unexpected body", 502)
        return data

    async def status(self) -> dict[str, Any]:
        """Never raises: an unreachable service is a status, shown on the console and the overview."""
        started = time.perf_counter()
        out: dict[str, Any] = {"configured": True, "url": self.url, "reachable": False, "ready": False}
        try:
            ready = await self.http.get(f"{self.url}/ready", timeout=3.0)
            out["reachable"] = True
            out["ready"] = ready.status_code == 200
            out["service"] = await self._call("GET", "/v1/status", timeout=5.0)
        except (httpx.HTTPError, SimulationUnavailable) as exc:
            out["error"] = (
                str(exc) if isinstance(exc, SimulationUnavailable) else f"unreachable ({exc.__class__.__name__})"
            )
        out["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
        return out

    async def events(self, p: Principal, limit: int) -> dict[str, Any]:
        p.require(Permission.READ)
        return await self._call("GET", "/v1/events", params={"limit": limit})

    async def scan(self, p: Principal, items: list[dict[str, Any]]) -> dict[str, Any]:
        p.require(Permission.CATALOG_WRITE)
        return await self._call("POST", "/v1/memory/scan", {"items": items})

    async def inspect(self, p: Principal, items: list[dict[str, Any]], scan: bool) -> dict[str, Any]:
        p.require(Permission.CATALOG_WRITE)
        out = await self._call("POST", "/v1/memory/inspect", {"items": items, "scan": scan})
        await self.ctx.log("memory-firewall", "inspect", "inspect", p.actor, after=out.get("summary") or {})
        return out

    async def self_test(self, p: Principal) -> dict[str, Any]:
        p.require(Permission.CATALOG_WRITE)
        out = await self._call("POST", "/v1/selftest/checkpoint", timeout=self.selftest_timeout)
        await self.ctx.log(
            "memory-firewall",
            "selftest",
            "self-test",
            p.actor,
            after={k: out.get(k) for k in ("passed", "guard_blocked", "attacks", "duration_ms")},
        )
        return out
