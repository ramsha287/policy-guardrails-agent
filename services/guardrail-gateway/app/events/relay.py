"""Outbox relay: publish guardrail.outbox rows to Redis pub/sub and/or a webhook, then mark them.

    loop:
      BEGIN
      SELECT ... WHERE published_at IS NULL ORDER BY id LIMIT 100 FOR UPDATE SKIP LOCKED
      publish the batch to every sink          (any failure -> ROLLBACK, retried with backoff)
      UPDATE ... SET published_at = now()
      COMMIT

At-least-once: a crash between publishing and COMMIT republishes the batch, so consumers dedupe
on the CloudEvents `id`. SKIP LOCKED lets every gateway replica run a relay without double work.
Published rows are deleted after OUTBOX_RETENTION_DAYS (7); unpublished rows are never deleted
(the backlog metric `guardrail_outbox_backlog` alerts instead).

Sinks (OUTBOX_SINKS, comma-separated):
  redis    PUBLISH events.<topic> <event JSON>        (fire-and-forget fan-out; use the webhook or
                                                       a Redis consumer that persists for durability)
  webhook  POST OUTBOX_WEBHOOK_URL, body = JSON array of events
           (Content-Type: application/cloudevents-batch+json),
           X-Guardrail-Timestamp: <unix seconds>,
           X-Guardrail-Signature: sha256=<hex HMAC-SHA256(OUTBOX_WEBHOOK_SECRET, "<timestamp>.<body>")>
           any non-2xx is a failure (retried)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Mapping, Sequence

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import OutboxEvent
from app.events.outbox import chain_heads_events
from app.events.sinks import RedisSink, Sink, WebhookSink, sign
from app.observability import OUTBOX_BACKLOG, OUTBOX_ERRORS, OUTBOX_PUBLISHED

__all__ = ["OutboxRelay", "RedisSink", "Sink", "WebhookSink", "sign"]

logger = logging.getLogger(__name__)


class OutboxRelay:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        sinks: Sequence[Sink],
        *,
        source: str,
        heads: Callable[[], Mapping[tuple[str, str], tuple[int, str]]] | None = None,
        batch_size: int = 100,
        poll_seconds: float = 1.0,
        retention_days: int = 7,
        chain_heads_seconds: float = 3600.0,
    ) -> None:
        self._sm = sessionmaker
        self.sinks = list(sinks)
        self._source = source
        self._heads = heads  # AuditWriter.written_heads: committed records only
        self._batch = batch_size
        self._poll = poll_seconds
        self._retention_days = retention_days
        self._heads_every = chain_heads_seconds
        self._tasks: list[asyncio.Task[None]] = []

    async def publish_once(self) -> int:
        """Publish one batch. Returns how many rows were published (0 = nothing to do)."""
        async with self._sm() as s, s.begin():
            rows = (
                await s.execute(
                    text(
                        "SELECT id, payload FROM guardrail.outbox WHERE published_at IS NULL "
                        "ORDER BY id LIMIT :n FOR UPDATE SKIP LOCKED"
                    ),
                    {"n": self._batch},
                )
            ).all()
            if not rows:
                return 0
            events = [r.payload if isinstance(r.payload, dict) else json.loads(r.payload) for r in rows]
            for sink in self.sinks:
                try:
                    await sink.publish(events)
                except Exception:
                    OUTBOX_ERRORS.labels(sink.name).inc()
                    raise  # rolls back: the rows stay unpublished and are retried
            await s.execute(
                text("UPDATE guardrail.outbox SET published_at = now() WHERE id = ANY(:ids)"),
                {"ids": [r.id for r in rows]},
            )
        OUTBOX_PUBLISHED.inc(len(rows))
        return len(rows)

    async def prune(self) -> int:
        async with self._sm() as s, s.begin():
            res = await s.execute(
                text("DELETE FROM guardrail.outbox WHERE published_at < now() - make_interval(days => :d)"),
                {"d": self._retention_days},
            )
            backlog = (
                await s.execute(text("SELECT count(*) FROM guardrail.outbox WHERE published_at IS NULL"))
            ).scalar()
        OUTBOX_BACKLOG.set(int(backlog or 0))
        return int(getattr(res, "rowcount", 0) or 0)

    async def export_chain_heads(self) -> int:
        if self._heads is None:
            return 0
        events = chain_heads_events(self._heads(), self._source)
        if not events:
            return 0
        async with self._sm() as s, s.begin():
            await s.execute(insert(OutboxEvent).on_conflict_do_nothing(index_elements=["event_id"]), events)
        return len(events)

    async def _publish_loop(self) -> None:
        backoff = self._poll
        while True:
            try:
                n = await self.publish_once()
                backoff = self._poll
                if n == self._batch:
                    continue  # more waiting: don't sleep
            except Exception as exc:  # noqa: BLE001 - keep relaying; the rows wait in Postgres
                logger.warning("outbox publish failed: %s", exc.__class__.__name__)
                backoff = min(backoff * 2, 60.0)
            await asyncio.sleep(backoff)

    async def _housekeeping_loop(self) -> None:
        last_heads = time.monotonic()
        while True:
            await asyncio.sleep(60)
            try:
                await self.prune()
                if time.monotonic() - last_heads >= self._heads_every:
                    last_heads = time.monotonic()
                    await self.export_chain_heads()
            except Exception as exc:  # noqa: BLE001
                logger.warning("outbox housekeeping failed: %s", exc.__class__.__name__)

    def start(self) -> None:
        self._tasks = [
            asyncio.create_task(self._publish_loop(), name="outbox-relay"),
            asyncio.create_task(self._housekeeping_loop(), name="outbox-housekeeping"),
        ]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self._heads is not None:  # the final heads of this process's chains
            try:
                await asyncio.wait_for(self.export_chain_heads(), 3.0)
                await asyncio.wait_for(self.publish_once(), 5.0)
            except Exception as exc:  # noqa: BLE001
                logger.warning("outbox: final chain-head export failed: %s", exc.__class__.__name__)
