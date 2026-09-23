"""State store for stateful guardrails (step limits, rate limits, anomaly baselines).

Keys are namespaced `guardrail:<guardrail_id>:<tenant_id>:<key>` by `scoped()`, so a plugin
cannot read another tenant's state by accident.
"""

from __future__ import annotations

from redis.asyncio import Redis


def scoped(guardrail_id: str, tenant_id: str, key: str) -> str:
    return f"guardrail:{guardrail_id}:{tenant_id}:{key}"


class RedisStateStore:
    def __init__(self, url: str) -> None:
        self._r = Redis.from_url(url, decode_responses=True)

    async def get(self, key: str) -> str | None:
        return await self._r.get(key)

    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        await self._r.set(key, value, ex=ttl_seconds)

    async def incr(self, key: str, ttl_seconds: int | None = None) -> int:
        async with self._r.pipeline(transaction=True) as p:
            p.incr(key)
            if ttl_seconds:
                p.expire(key, ttl_seconds, nx=True)
            value, *_ = await p.execute()
        return int(value)

    async def ping(self) -> bool:
        try:
            return bool(await self._r.ping())
        except Exception:  # noqa: BLE001
            return False

    async def close(self) -> None:
        await self._r.aclose()
