"""GuardedSaver: the memory firewall around a LangGraph checkpoint saver.

On every write it signs the stored bytes into the separate ledger (checkpoint, metadata and
pending writes). On every load it VERIFIES the raw stored bytes BEFORE the inner saver is
allowed to deserialize them (brief §8 #1). Anything that fails - edited content, an
unsigned/forged blob, a replayed or truncated checkpoint, a blob moved between threads - is
refused (fail closed) and logged with a MITRE ATLAS tag; the agent never loads it.

Write-path hashes are computed from the objects exactly as SqliteSaver serializes them, so
the write path never reads the DB (avoiding cursor races with LangGraph's worker threads).
The load path reads through a dedicated connection (WAL + busy timeout).

Scope (brief §7): this measures integrity, not RCE. The inner serializer is the plain
JsonPlusSerializer, so Guard's protection comes from signatures + lineage, not secrecy.
"""

import hashlib
import json
import sqlite3
import threading
from pathlib import Path

from langgraph.checkpoint.base import BaseCheckpointSaver, get_checkpoint_metadata
from langgraph.checkpoint.sqlite import WRITES_IDX_MAP

from guard.events import EventLog
from guard.keys import load_or_create_signer, load_verifier
from guard.ledger import Ledger


class GuardViolation(Exception):
    """Raised when stored memory fails verification. The firewall refuses to load it."""


def _as_bytes(x) -> bytes:
    if x is None:
        return b""
    if isinstance(x, memoryview):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("utf-8")
    return bytes(x)


def _sha(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


class GuardedSaver(BaseCheckpointSaver):
    def __init__(self, inner: BaseCheckpointSaver, db_path: Path, ledger: Ledger, events: EventLog) -> None:
        super().__init__(serde=inner.serde)
        self.inner = inner
        self.ledger = ledger
        self.events = events
        # Dedicated read connection for load-time verification (separate from the writer).
        self._read = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        self._read.execute("PRAGMA journal_mode=WAL")
        self._read.execute("PRAGMA busy_timeout=30000")
        self._rlock = threading.Lock()

    @property
    def config_specs(self):
        return self.inner.config_specs

    @property
    def conn(self):
        return self.inner.conn

    # --- hashes computed from the objects, matching SqliteSaver's stored bytes --------

    def _checkpoint_hashes(self, config, checkpoint, metadata) -> tuple[bytes, bytes]:
        type_, blob = self.inner.serde.dumps_typed(checkpoint)
        meta = json.dumps(get_checkpoint_metadata(config, metadata), ensure_ascii=False).encode("utf-8", "ignore")
        return _sha(_as_bytes(type_), _as_bytes(blob)), _sha(meta)

    def _writes_hash_from_objs(self, writes) -> bytes:
        items = []
        for idx, (channel, value) in enumerate(writes):
            typ, val = self.inner.serde.dumps_typed(value)
            items.append((WRITES_IDX_MAP.get(channel, idx), channel, typ, val))
        items.sort(key=lambda r: r[0])
        parts = [_sha(str(i).encode(), _as_bytes(c), _as_bytes(t), _as_bytes(v)) for i, c, t, v in items]
        return _sha(*parts)

    # --- raw-byte access for the LOAD path (dedicated read connection) ---------------

    def _ckpt_row(self, thread_id, ns, checkpoint_id):
        with self._rlock:
            return self._read.execute(
                "SELECT type, checkpoint, metadata FROM checkpoints "
                "WHERE thread_id=? AND checkpoint_ns=? AND checkpoint_id=?",
                (thread_id, ns, checkpoint_id),
            ).fetchone()

    def _latest_id(self, thread_id, ns):
        with self._rlock:
            row = self._read.execute(
                "SELECT checkpoint_id FROM checkpoints WHERE thread_id=? AND checkpoint_ns=? "
                "ORDER BY checkpoint_id DESC LIMIT 1",
                (thread_id, ns),
            ).fetchone()
        return row[0] if row else None

    def _stored_writes_hashes(self, thread_id, ns, checkpoint_id) -> dict[str, bytes]:
        with self._rlock:
            rows = self._read.execute(
                "SELECT task_id, idx, channel, type, value FROM writes "
                "WHERE thread_id=? AND checkpoint_ns=? AND checkpoint_id=? ORDER BY task_id, idx",
                (thread_id, ns, checkpoint_id),
            ).fetchall()
        by_task: dict[str, list] = {}
        for task_id, idx, channel, typ, value in rows:
            by_task.setdefault(task_id, []).append(
                _sha(str(idx).encode(), _as_bytes(channel), _as_bytes(typ), _as_bytes(value))
            )
        return {task: _sha(*parts) for task, parts in by_task.items()}

    # --- write paths (no DB read) ---------------------------------------------------

    def put(self, config, checkpoint, metadata, new_versions):
        blob_hash, meta_hash = self._checkpoint_hashes(config, checkpoint, metadata)
        result = self.inner.put(config, checkpoint, metadata, new_versions)
        cfg = result["configurable"]
        thread_id, ns, checkpoint_id = cfg["thread_id"], cfg.get("checkpoint_ns", ""), cfg["checkpoint_id"]
        parent_id = config["configurable"].get("checkpoint_id")
        self.ledger.record_checkpoint(thread_id, ns, checkpoint_id, parent_id, blob_hash, meta_hash)
        self.events.write(thread_id, checkpoint_id, ns)
        return result

    def put_writes(self, config, writes, task_id, task_path=""):
        writes_hash = self._writes_hash_from_objs(writes)
        self.inner.put_writes(config, writes, task_id, task_path)
        cfg = config["configurable"]
        self.ledger.record_writes(cfg["thread_id"], cfg.get("checkpoint_ns", ""), cfg["checkpoint_id"], task_id, writes_hash)

    # --- load path (verify BEFORE the inner saver deserializes) ----------------------

    def get_tuple(self, config):
        cfg = config["configurable"]
        thread_id, ns = cfg["thread_id"], cfg.get("checkpoint_ns", "")
        requested = cfg.get("checkpoint_id")
        target = requested or self._latest_id(thread_id, ns)
        if target is None:
            return self.inner.get_tuple(config)  # nothing stored yet

        row = self._ckpt_row(thread_id, ns, target)
        if row is None:
            return self.inner.get_tuple(config)
        typ, blob, meta = row
        blob_hash, meta_hash = _sha(_as_bytes(typ), _as_bytes(blob)), _sha(_as_bytes(meta))

        ok, reason = self.ledger.verify_checkpoint(thread_id, ns, target, blob_hash, meta_hash)
        if ok and requested is None:
            anchored = self.ledger.head(thread_id, ns)
            if anchored is not None and anchored != target:
                ok, reason = False, "latest checkpoint missing (truncation/rollback)"
        if ok:
            for task_id, wh in self._stored_writes_hashes(thread_id, ns, target).items():
                wok, wreason = self.ledger.verify_writes(thread_id, ns, target, task_id, wh)
                if not wok:
                    ok, reason = False, wreason
                    break
        if not ok:
            self.events.reject(thread_id, target, reason, ns)
            raise GuardViolation(f"{reason} [thread={thread_id} checkpoint={target}]")

        self.events.load(thread_id, target, ns)
        return self.inner.get_tuple(config)

    def list(self, *a, **kw):
        return self.inner.list(*a, **kw)

    def get_next_version(self, current, channel=None):
        return self.inner.get_next_version(current, channel)

    def close(self) -> None:
        with self._rlock:
            self._read.close()
        self.ledger.close()
        self.inner.conn.close()


def make_guarded_saver(db_path: Path, inner_saver: BaseCheckpointSaver,
                       ledger_path: Path, key_dir: Path, events_path: Path) -> GuardedSaver:
    signer = load_or_create_signer(key_dir)
    verifier = load_verifier(key_dir)
    ledger = Ledger(ledger_path, signer, verifier)
    events = EventLog(events_path)
    return GuardedSaver(inner_saver, db_path, ledger, events)
