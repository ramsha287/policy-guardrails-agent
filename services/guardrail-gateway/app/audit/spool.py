"""Durable spill-over for audit events (the "outbox" for when Postgres is slow or down).

Events that can't be written (the database is down after retries, or the in-memory queue is
full) are appended to JSON-lines files in AUDIT_SPOOL_DIR instead of being dropped. The writer
replays the files, oldest first, as soon as the database accepts writes again. Inserts are
idempotent (ON CONFLICT DO NOTHING on the event id), so a replay after a partial failure never
duplicates rows.

The spool is bounded by AUDIT_SPOOL_MAX_MB; past that, events are dropped and counted in
`audit_events_dropped_total` (alerted on). On Kubernetes, put the directory on a volume that
survives container restarts (the chart uses an emptyDir by default, or a PVC if you enable one).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AuditSpool:
    def __init__(self, directory: Path, max_bytes: int = 512 * 1024 * 1024) -> None:
        self.dir = directory
        self.max_bytes = max_bytes
        self._lock = threading.Lock()  # append/remove run in worker threads
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error("Audit spool directory %s is not usable: %s", directory, exc)
        self._size = self._scan_size()

    def _scan_size(self) -> int:
        total = 0
        for f in self.files():
            try:
                total += f.stat().st_size
            except OSError:  # removed while scanning
                pass
        return total

    def size_bytes(self) -> int:
        """Bytes waiting to be replayed (tracked, not rescanned)."""
        return self._size

    def files(self) -> list[Path]:
        try:
            return sorted(self.dir.glob("audit-*.jsonl"))
        except OSError:
            return []

    def append(self, events: list[dict[str, Any]]) -> bool:
        """Write events to a new spool file. False when the spool is full or not writable."""
        if not events:
            return True
        data = "".join(json.dumps(e, default=_jsonable, separators=(",", ":")) + "\n" for e in events).encode()
        with self._lock:
            if self._size + len(data) > self.max_bytes:
                return False
            tmp: str | None = None
            try:
                # time-ordered names so replay keeps the original order
                name = f"audit-{time.time_ns():020d}-{uuid.uuid4().hex[:8]}.jsonl"
                fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".audit-")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.dir / name)  # atomic: a reader never sees half a file
                tmp = None
                self._size += len(data)
                return True
            except OSError as exc:
                logger.error("Audit spool write failed: %s", exc)
                return False
            finally:
                if tmp is not None:  # failed half-way (e.g. disk full): don't leave the temp file
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass

    @staticmethod
    def read(path: Path) -> list[dict[str, Any]]:
        events = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            e["id"] = uuid.UUID(e["id"])
            e["created_at"] = datetime.fromisoformat(e["created_at"])
            events.append(e)
        return events

    def remove(self, path: Path) -> None:
        with self._lock:
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            path.unlink(missing_ok=True)
            self._size = max(0, self._size - size)

    def quarantine(self, path: Path) -> None:
        """Move an unreadable file aside (kept for inspection, no longer counted or replayed)."""
        with self._lock:
            try:
                size = path.stat().st_size
                path.rename(path.with_suffix(".bad"))
                self._size = max(0, self._size - size)
            except OSError as exc:
                logger.error("Could not move %s aside: %s", path.name, exc)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    return str(value)
