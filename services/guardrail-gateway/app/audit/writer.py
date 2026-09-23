"""Audit writer: decisions go to an in-memory queue and are batch-inserted in the background.

The request path only does `queue.put_nowait`, so audit never adds latency. If the queue is
full (database down for a long time) events are dropped and counted in
`audit_events_dropped_total`, which is alerted on. A durable outbox is planned for phase 5.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import AuditEvent
from app.observability import AUDIT_DROPPED, AUDIT_WRITTEN

logger = logging.getLogger(__name__)


def payload_digest(payload: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON payload. The raw payload itself is never stored."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditSink(Protocol):
    def submit(self, event: dict[str, Any]) -> None: ...


class AuditWriter:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        *,
        queue_size: int = 10_000,
        batch_size: int = 200,
        flush_seconds: float = 1.0,
        retention_months: int = 12,
    ) -> None:
        self._sm = sessionmaker
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
        self._batch_size = batch_size
        self._flush_seconds = flush_seconds
        self._retention_months = retention_months
        self._task: asyncio.Task[None] | None = None
        self._maint_task: asyncio.Task[None] | None = None

    def submit(self, event: dict[str, Any]) -> None:
        event.setdefault("id", uuid.uuid4())
        event.setdefault("created_at", datetime.now(UTC))
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            AUDIT_DROPPED.inc()
            logger.error("Audit queue full; dropping event for request %s", event.get("request_id"))

    async def start(self) -> None:
        await self.maintain_partitions()
        self._task = asyncio.create_task(self._run(), name="audit-writer")
        self._maint_task = asyncio.create_task(self._maintenance_loop(), name="audit-maintenance")

    async def stop(self) -> None:
        for t in (self._maint_task, self._task):
            if t:
                t.cancel()
        for t in (self._maint_task, self._task):
            if t:
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        await self._drain()

    async def _take_batch(self) -> list[dict[str, Any]]:
        batch = [await self._queue.get()]
        deadline = asyncio.get_running_loop().time() + self._flush_seconds
        while len(batch) < self._batch_size:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(self._queue.get(), timeout=remaining))
            except TimeoutError:
                break
        return batch

    async def _write(self, batch: list[dict[str, Any]]) -> None:
        async with self._sm() as s:
            # ON CONFLICT DO NOTHING makes a retried batch idempotent.
            await s.execute(insert(AuditEvent).on_conflict_do_nothing(), batch)
            await s.commit()
        AUDIT_WRITTEN.inc(len(batch))

    async def _run(self) -> None:
        while True:
            batch = await self._take_batch()
            for attempt in range(3):
                try:
                    await self._write(batch)
                    break
                except asyncio.CancelledError:
                    for e in batch:  # put back so stop() can drain them
                        self.submit(e)
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.error("Audit write failed (attempt %d): %s", attempt + 1, exc.__class__.__name__)
                    await asyncio.sleep(0.5 * (attempt + 1))
            else:
                AUDIT_DROPPED.inc(len(batch))

    async def _drain(self) -> None:
        batch: list[dict[str, Any]] = []
        while not self._queue.empty():
            batch.append(self._queue.get_nowait())
            if len(batch) >= self._batch_size:
                await self._safe_write(batch)
                batch = []
        if batch:
            await self._safe_write(batch)

    async def _safe_write(self, batch: list[dict[str, Any]]) -> None:
        try:
            await self._write(batch)
        except Exception as exc:  # noqa: BLE001
            AUDIT_DROPPED.inc(len(batch))
            logger.error("Audit drain failed: %s", exc.__class__.__name__)

    async def maintain_partitions(self) -> None:
        """Create upcoming monthly partitions and drop those past retention (12 months by default)."""
        try:
            async with self._sm() as s:
                await s.execute(text("SELECT audit.ensure_partitions(3)"))
                dropped = (
                    await s.execute(text("SELECT audit.drop_partitions_older_than(:m)"), {"m": self._retention_months})
                ).scalar()
                await s.commit()
            if dropped:
                logger.info("Dropped %d audit partition(s) past %d-month retention", dropped, self._retention_months)
        except Exception as exc:  # noqa: BLE001
            logger.error("Audit partition maintenance failed: %s", exc.__class__.__name__)

    async def _maintenance_loop(self) -> None:
        while True:
            await asyncio.sleep(6 * 3600)
            await self.maintain_partitions()
