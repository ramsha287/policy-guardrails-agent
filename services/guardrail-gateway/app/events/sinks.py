"""Where outbox events go (see app/events/relay.py for the delivery guarantees)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from collections.abc import Callable, Sequence
from typing import Any, Protocol

import httpx


class Sink(Protocol):
    name: str

    async def publish(self, events: Sequence[dict[str, Any]]) -> None: ...


class RedisSink:
    name = "redis"

    def __init__(self, redis: Any, prefix: str = "events") -> None:
        self._r = redis
        self._prefix = prefix

    async def publish(self, events: Sequence[dict[str, Any]]) -> None:
        pipe = self._r.pipeline(transaction=False)
        for ev in events:
            topic = str(ev.get("type", "")).removeprefix("io.guardrail.")
            pipe.publish(f"{self._prefix}.{topic}", json.dumps(ev, separators=(",", ":")))
        await asyncio.wait_for(pipe.execute(), 5.0)


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


class WebhookSink:
    name = "webhook"

    def __init__(self, http: httpx.AsyncClient, url: str, secret: str | None, clock: Callable[[], float] = time.time):
        self._http = http
        self._url = url
        self._secret = secret
        self._now = clock

    async def publish(self, events: Sequence[dict[str, Any]]) -> None:
        body = json.dumps(list(events), separators=(",", ":")).encode()
        ts = str(int(self._now()))
        headers = {"Content-Type": "application/cloudevents-batch+json", "X-Guardrail-Timestamp": ts}
        if self._secret:
            headers["X-Guardrail-Signature"] = sign(self._secret, ts, body)
        resp = await self._http.post(self._url, content=body, headers=headers, timeout=10.0)
        if resp.status_code // 100 != 2:
            raise RuntimeError(f"webhook answered {resp.status_code}")
