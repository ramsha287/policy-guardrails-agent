"""Where pending verifications and request-bound evidence live (Redis, or per-replica memory).

Keys (prefix "grv"):
  ver:{tenant}:{id}             -> Verification JSON
  pend:{tenant}:{request_hash}  -> id of the open verification (a retry doesn't open a second one)
  ev:{tenant}:{request_hash}    -> list of Evidence JSON
All expire on their own (10 minutes). Evidence is consumed (deleted) when the request it was made
for is allowed, so it works once.

Without Redis a confirmation must reach the same replica that created the verification; run Redis
when the gateway has more than one replica (the Helm chart does).
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Any, Protocol

from app.verify.model import Evidence, Verification


class VerificationStore(Protocol):
    async def put_verification(self, v: Verification) -> None: ...
    async def get_verification(self, tenant: str, vid: str) -> Verification | None: ...
    async def pending_for(self, tenant: str, request_hash: str) -> Verification | None: ...
    async def add_evidence(self, tenant: str, ev: Evidence) -> None: ...
    async def evidence(self, tenant: str, request_hash: str) -> list[Evidence]: ...
    async def consume_evidence(self, tenant: str, request_hash: str) -> None: ...
    async def take_evidence(self, tenant: str, request_hash: str) -> list[Evidence]: ...


class MemoryVerificationStore:
    def __init__(self, max_entries: int = 20_000, clock: Any = time.time) -> None:
        self._now = clock
        self._max = max_entries
        self._ver: OrderedDict[tuple[str, str], Verification] = OrderedDict()
        self._pend: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._ev: OrderedDict[tuple[str, str], list[Evidence]] = OrderedDict()

    def _trim(self, d: OrderedDict[Any, Any]) -> None:
        while len(d) > self._max:
            d.popitem(last=False)

    async def put_verification(self, v: Verification) -> None:
        self._ver[(v.tenant_id, v.id)] = v
        self._ver.move_to_end((v.tenant_id, v.id))
        self._trim(self._ver)
        if v.status == "pending":
            self._pend[(v.tenant_id, v.request_hash)] = v.id
            self._trim(self._pend)

    async def pending_for(self, tenant: str, request_hash: str) -> Verification | None:
        vid = self._pend.get((tenant, request_hash))
        v = await self.get_verification(tenant, vid) if vid else None
        return v if v is not None and v.status == "pending" else None

    async def get_verification(self, tenant: str, vid: str) -> Verification | None:
        v = self._ver.get((tenant, vid))
        if v is None:
            return None
        if v.status == "pending" and v.expires_at <= self._now():
            return Verification(**{**v.__dict__, "status": "expired"})
        return v

    async def add_evidence(self, tenant: str, ev: Evidence) -> None:
        self._ev.setdefault((tenant, ev.request_hash), []).append(ev)
        self._ev.move_to_end((tenant, ev.request_hash))
        self._trim(self._ev)

    async def evidence(self, tenant: str, request_hash: str) -> list[Evidence]:
        now = self._now()
        return [e for e in self._ev.get((tenant, request_hash), []) if e.expires_at > now]

    async def consume_evidence(self, tenant: str, request_hash: str) -> None:
        self._ev.pop((tenant, request_hash), None)

    async def take_evidence(self, tenant: str, request_hash: str) -> list[Evidence]:
        """Atomically read and delete: of two concurrent identical retries, only one gets it."""
        now = self._now()
        return [e for e in self._ev.pop((tenant, request_hash), []) if e.expires_at > now]


class RedisVerificationStore:
    def __init__(self, redis: Any, prefix: str = "grv", clock: Any = time.time, timeout_seconds: float = 0.25) -> None:
        self._r = redis
        self._p = prefix
        self._now = clock
        self._timeout = timeout_seconds

    def _k(self, *parts: str) -> str:
        return ":".join((self._p, *parts))

    async def _run(self, *ops: tuple[str, tuple[Any, ...], dict[str, Any]], atomic: bool = False) -> list[Any]:
        pipe = self._r.pipeline(transaction=atomic)
        for name, args, kwargs in ops:
            getattr(pipe, name)(*args, **kwargs)
        return list(await asyncio.wait_for(pipe.execute(), self._timeout))

    async def put_verification(self, v: Verification) -> None:
        ttl = max(1, int(v.expires_at - self._now()) + 60)
        ops: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = [
            ("set", (self._k("ver", v.tenant_id, v.id), v.to_json()), {"ex": ttl})
        ]
        if v.status == "pending":
            ops.append(("set", (self._k("pend", v.tenant_id, v.request_hash), v.id), {"ex": ttl}))
        await self._run(*ops)

    async def pending_for(self, tenant: str, request_hash: str) -> Verification | None:
        try:
            (vid,) = await self._run(("get", (self._k("pend", tenant, request_hash),), {}))
        except Exception:  # noqa: BLE001 - worst case a retry opens a second verification
            return None
        if not vid:
            return None
        v = await self.get_verification(tenant, vid.decode() if isinstance(vid, bytes) else vid)
        return v if v is not None and v.status == "pending" else None

    async def get_verification(self, tenant: str, vid: str) -> Verification | None:
        try:
            (raw,) = await self._run(("get", (self._k("ver", tenant, vid),), {}))
        except Exception:  # noqa: BLE001 - unknown is "not found": nothing is confirmed by accident
            return None
        if not raw:
            return None
        v = Verification.from_json(raw.decode() if isinstance(raw, bytes) else raw)
        if v.status == "pending" and v.expires_at <= self._now():
            return Verification(**{**v.__dict__, "status": "expired"})
        return v

    async def add_evidence(self, tenant: str, ev: Evidence) -> None:
        k = self._k("ev", tenant, ev.request_hash)
        ttl = max(1, int(ev.expires_at - self._now()))
        await self._run(("rpush", (k, ev.to_json()), {}), ("expire", (k, ttl), {}))

    async def evidence(self, tenant: str, request_hash: str) -> list[Evidence]:
        try:
            (items,) = await self._run(("lrange", (self._k("ev", tenant, request_hash), 0, 49), {}))
        except Exception:  # noqa: BLE001 - no evidence (stricter), never an error
            return []
        return self._parse(items, request_hash)

    async def take_evidence(self, tenant: str, request_hash: str) -> list[Evidence]:
        """MULTI/EXEC read-and-delete. Errors propagate: the caller then holds (fails closed)
        rather than allowing on evidence it couldn't consume."""
        k = self._k("ev", tenant, request_hash)
        items, _ = await self._run(("lrange", (k, 0, 49), {}), ("delete", (k,), {}), atomic=True)
        return self._parse(items, request_hash)

    def _parse(self, items: Any, request_hash: str) -> list[Evidence]:
        now = self._now()
        out = []
        for raw in items:
            try:
                ev = Evidence.from_json(raw.decode() if isinstance(raw, bytes) else raw)
            except (ValueError, TypeError, KeyError):
                continue
            if ev.expires_at > now and ev.request_hash == request_hash:
                out.append(ev)
        return out

    async def consume_evidence(self, tenant: str, request_hash: str) -> None:
        try:
            await self._run(("delete", (self._k("ev", tenant, request_hash),), {}))
        except Exception:  # noqa: BLE001 - expires on its own within minutes
            return
