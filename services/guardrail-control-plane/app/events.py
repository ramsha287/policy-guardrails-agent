"""Change notifications to gateways (Redis pub/sub). Gateways also poll, so events are an
optimisation: a lost event delays a change by at most one poll interval."""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol

logger = logging.getLogger(__name__)

SNAPSHOT_CHANNEL = "guardrail:snapshot.published"
CATALOG_CHANNEL = "guardrail:catalog.published"


class EventPublisher(Protocol):
    async def publish(self, channel: str, message: dict[str, Any]) -> None: ...


class NullPublisher:
    async def publish(self, channel: str, message: dict[str, Any]) -> None:
        return None


class MemoryPublisher:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def publish(self, channel: str, message: dict[str, Any]) -> None:
        self.events.append((channel, message))


class RedisPublisher:
    def __init__(self, url: str) -> None:
        from redis.asyncio import Redis

        self._redis = Redis.from_url(url, decode_responses=True)

    async def publish(self, channel: str, message: dict[str, Any]) -> None:
        try:
            await self._redis.publish(channel, json.dumps(message))
        except Exception as exc:  # noqa: BLE001 - gateways still poll
            logger.warning("Could not publish %s: %s", channel, exc.__class__.__name__)

    async def close(self) -> None:
        await self._redis.aclose()
