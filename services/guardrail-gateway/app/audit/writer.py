"""Audit writer: decisions go to an in-memory queue and are batch-inserted in the background.

The request path only does `queue.put_nowait`, so audit never adds latency. Events that can't
be written (database down after retries, or the queue full) go to the disk spool
(app/audit/spool.py) and are replayed when the database is back. Only when the spool is full or
missing are events dropped, counted in `audit_events_dropped_total` (alerted on).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.digest import payload_digest
from app.audit.spool import AuditSpool
from app.db.models import AuditEvent
from app.observability import AUDIT_DROPPED, AUDIT_SPOOL_BYTES, AUDIT_SPOOLED, AUDIT_WRITTEN

__all__ = ["AuditSink", "AuditWriter", "payload_digest"]

logger = logging.getLogger(__name__)


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
        maintenance: bool = True,
        spool: AuditSpool | None = None,
        replay_seconds: float = 10.0,
        drain_timeout_seconds: float = 5.0,
    ) -> None:
        self._sm = sessionmaker
        self._maintenance = maintenance
        self._spool = spool
        self._replay_seconds = replay_seconds
        self._replay_task: asyncio.Task[None] | None = None
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
        self._batch_size = batch_size
        self._flush_seconds = flush_seconds
        self._retention_months = retention_months
        self._task: asyncio.Task[None] | None = None
        self._maint_task: asyncio.Task[None] | None = None
        # Events taken off the queue but not yet written or spooled. They survive cancellation
        # (stop() drains them), so a shutdown in the middle of a batch loses nothing.
        self._inflight: list[dict[str, Any]] = []
        # Queue overflow waits here (bounded) and is spooled in one file per second by a
        # background task, so the request path never touches the disk.
        self._overflow: list[dict[str, Any]] = []
        self._overflow_max = max(1_000, queue_size)
        self._drain_timeout = drain_timeout_seconds
        self._overflow_task: asyncio.Task[None] | None = None

    def submit(self, event: dict[str, Any]) -> None:
        event.setdefault("id", uuid.uuid4())
        event.setdefault("created_at", datetime.now(UTC))
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            if self._spool is not None and len(self._overflow) < self._overflow_max:
                self._overflow.append(event)
            else:
                AUDIT_DROPPED.inc()
                logger.error("Audit queue and overflow full; dropping event for request %s", event.get("request_id"))

    async def start(self) -> None:
        if self._maintenance:  # otherwise a CronJob runs `python -m app.cli partitions`
            await self.maintain_partitions()
            self._maint_task = asyncio.create_task(self._maintenance_loop(), name="audit-maintenance")
        self._task = asyncio.create_task(self._run(), name="audit-writer")
        if self._spool is not None:
            self._replay_task = asyncio.create_task(self._replay_loop(), name="audit-replay")
            self._overflow_task = asyncio.create_task(self._overflow_loop(), name="audit-overflow")

    async def _spill(self, events: list[dict[str, Any]], why: str) -> None:
        """Keep events on disk instead of dropping them; drop (and count) only if that fails too."""
        if not events:
            return
        if self._spool is not None and await asyncio.to_thread(self._spool.append, events):
            AUDIT_SPOOLED.inc(len(events))
            AUDIT_SPOOL_BYTES.set(self._spool.size_bytes())
            logger.warning("Audit: %d event(s) spooled to disk (%s)", len(events), why)
            return
        AUDIT_DROPPED.inc(len(events))
        logger.error("Audit: %d event(s) dropped (%s; spool unavailable or full)", len(events), why)

    async def _flush_overflow(self) -> None:
        batch, self._overflow = self._overflow, []
        await self._spill(batch, "queue full")

    async def _overflow_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            await self._flush_overflow()

    async def replay_spool(self) -> int:
        """Write spooled files, oldest first; stop at the first database failure. Returns events written."""
        if self._spool is None:
            return 0
        written = 0
        for path in self._spool.files():
            try:
                events = await asyncio.to_thread(self._spool.read, path)
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
                logger.error("Audit spool file %s is unreadable (%s); moving it aside", path.name, exc)
                self._spool.quarantine(path)
                continue
            try:
                for i in range(0, len(events), self._batch_size):
                    await self._write(events[i : i + self._batch_size])
            except Exception as exc:  # noqa: BLE001 - database still down; try again later
                logger.warning("Audit spool replay paused: %s", exc.__class__.__name__)
                break
            self._spool.remove(path)
            written += len(events)
        AUDIT_SPOOL_BYTES.set(self._spool.size_bytes())
        if written:
            logger.info("Audit spool: replayed %d event(s)", written)
        return written

    async def _replay_loop(self) -> None:
        while True:
            try:
                await self.replay_spool()
            except Exception as exc:  # noqa: BLE001 - never let the replay task die; the spool would only grow
                logger.error("Audit spool replay failed: %s", exc.__class__.__name__, exc_info=exc)
            await asyncio.sleep(self._replay_seconds)

    async def stop(self) -> None:
        tasks = (self._maint_task, self._replay_task, self._overflow_task, self._task)
        for t in tasks:
            if t:
                t.cancel()
        for t in tasks:
            if t:
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        await self._drain()

    async def _take_batch(self) -> list[dict[str, Any]]:
        """Fill self._inflight from the queue (up to batch_size, or flush_seconds after the first)."""
        if not self._inflight:
            self._inflight.append(await self._queue.get())
        deadline = asyncio.get_running_loop().time() + self._flush_seconds
        while len(self._inflight) < self._batch_size:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                self._inflight.append(await asyncio.wait_for(self._queue.get(), timeout=remaining))
            except TimeoutError:
                break
        return self._inflight

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
                except Exception as exc:  # noqa: BLE001 (CancelledError is not an Exception: batch stays in _inflight)
                    logger.error("Audit write failed (attempt %d): %s", attempt + 1, exc.__class__.__name__)
                    if attempt < 2:
                        await asyncio.sleep(0.5 * (attempt + 1))
            else:
                await self._spill(list(batch), "database write failed 3 times")
            self._inflight = []

    async def _drain(self) -> None:
        """At shutdown: in-flight batch, queue and overflow, written if possible, else spooled."""
        pending = list(self._inflight) + list(self._overflow)
        self._inflight, self._overflow = [], []
        while not self._queue.empty():
            pending.append(self._queue.get_nowait())
        for i in range(0, len(pending), self._batch_size):
            await self._safe_write(pending[i : i + self._batch_size])

    async def _safe_write(self, batch: list[dict[str, Any]]) -> None:
        # Bounded: a hung database must not hold up shutdown; the batch goes to the spool instead.
        try:
            await asyncio.wait_for(self._write(batch), timeout=self._drain_timeout)
        except Exception as exc:  # noqa: BLE001 (includes TimeoutError)
            await self._spill(batch, f"drain at shutdown failed: {exc.__class__.__name__}")

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
