"""Signed lineage ledger + head anchor, stored SEPARATELY from the checkpoint database.

For every legitimately written checkpoint (and pending-writes batch) Guard records a signed
entry binding it to its thread, namespace, position and content hash, chained to the previous
entry for that thread (hash-chain lineage, brief §8). A per-thread head anchor records the
last checkpoint written. Because this store lives outside the checkpoint DB, deleting or
rolling back checkpoints in the DB is detectable: the head anchor still names the real latest
checkpoint, and the chain still names every genuine entry.

Threat model (brief §5): the attacker can write the checkpoint DB but not this store or the
signing key. Each entry is additionally signed, so even tampering with this file is evident.
"""

import hashlib
import sqlite3
import threading
from pathlib import Path

from guard.keys import Signer, Verifier

GENESIS = b"\x00" * 32


def _h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(len(p).to_bytes(8, "big"))
        m.update(p)
    return m.digest()


def _b(s: str) -> bytes:
    return s.encode("utf-8")


class Ledger:
    def __init__(self, path: Path, signer: Signer, verifier: Verifier) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        # WAL + NORMAL: durable, but avoids a full fsync on every signed write (keeps overhead low).
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        # One sqlite connection shared across LangGraph's worker threads; serialize access.
        self._lock = threading.RLock()
        self.signer = signer
        self.verifier = verifier
        self._setup()

    def _setup(self) -> None:
        with self._lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS entries (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    thread_id TEXT, ns TEXT, checkpoint_id TEXT, parent_id TEXT,
                    blob_hash BLOB, meta_hash BLOB, prev_entry_hash BLOB,
                    entry_hash BLOB, signature BLOB,
                    UNIQUE(thread_id, ns, checkpoint_id)
                );
                CREATE TABLE IF NOT EXISTS writes (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    thread_id TEXT, ns TEXT, checkpoint_id TEXT, task_id TEXT,
                    writes_hash BLOB, entry_hash BLOB, signature BLOB,
                    UNIQUE(thread_id, ns, checkpoint_id, task_id)
                );
                CREATE TABLE IF NOT EXISTS head (
                    thread_id TEXT, ns TEXT,
                    checkpoint_id TEXT, entry_hash BLOB, seq INTEGER, signature BLOB,
                    PRIMARY KEY(thread_id, ns)
                );
                """
            )

    # --- writing (called on put / put_writes) ---------------------------------------

    def _last_entry_hash(self, thread_id: str, ns: str) -> bytes:
        row = self.conn.execute(
            "SELECT entry_hash FROM entries WHERE thread_id=? AND ns=? ORDER BY seq DESC LIMIT 1",
            (thread_id, ns),
        ).fetchone()
        return row[0] if row else GENESIS

    def record_checkpoint(self, thread_id, ns, checkpoint_id, parent_id, blob_hash, meta_hash) -> None:
        with self._lock:
            prev = self._last_entry_hash(thread_id, ns)
            entry_hash = _h(_b("ckpt"), _b(thread_id), _b(ns), _b(checkpoint_id),
                            _b(parent_id or ""), blob_hash, meta_hash, prev)
            sig = self.signer.sign(entry_hash)
            self.conn.execute(
                "INSERT OR REPLACE INTO entries "
                "(thread_id, ns, checkpoint_id, parent_id, blob_hash, meta_hash, prev_entry_hash, entry_hash, signature) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (thread_id, ns, checkpoint_id, parent_id, blob_hash, meta_hash, prev, entry_hash, sig),
            )
            self._set_head(thread_id, ns, checkpoint_id, entry_hash)

    def record_writes(self, thread_id, ns, checkpoint_id, task_id, writes_hash) -> None:
        with self._lock:
            entry_hash = _h(_b("writes"), _b(thread_id), _b(ns), _b(checkpoint_id), _b(task_id), writes_hash)
            sig = self.signer.sign(entry_hash)
            self.conn.execute(
                "INSERT OR REPLACE INTO writes "
                "(thread_id, ns, checkpoint_id, task_id, writes_hash, entry_hash, signature) VALUES (?,?,?,?,?,?,?)",
                (thread_id, ns, checkpoint_id, task_id, writes_hash, entry_hash, sig),
            )

    def _set_head(self, thread_id, ns, checkpoint_id, entry_hash) -> None:
        seq = self.conn.execute("SELECT COALESCE(MAX(seq),0)+1 FROM entries").fetchone()[0]
        anchor = _h(_b("head"), _b(thread_id), _b(ns), _b(checkpoint_id), entry_hash, seq.to_bytes(8, "big"))
        sig = self.signer.sign(anchor)
        self.conn.execute(
            "INSERT OR REPLACE INTO head (thread_id, ns, checkpoint_id, entry_hash, seq, signature) VALUES (?,?,?,?,?,?)",
            (thread_id, ns, checkpoint_id, entry_hash, seq, sig),
        )

    # --- verifying (called on get_tuple) --------------------------------------------

    def verify_checkpoint(self, thread_id, ns, checkpoint_id, blob_hash, meta_hash) -> tuple[bool, str]:
        with self._lock:
            row = self.conn.execute(
                "SELECT parent_id, blob_hash, meta_hash, prev_entry_hash, entry_hash, signature "
                "FROM entries WHERE thread_id=? AND ns=? AND checkpoint_id=?",
                (thread_id, ns, checkpoint_id),
            ).fetchone()
        if row is None:
            return False, "no ledger entry (unsigned or forged checkpoint)"
        parent_id, exp_blob, exp_meta, prev, entry_hash, sig = row
        recomputed = _h(_b("ckpt"), _b(thread_id), _b(ns), _b(checkpoint_id),
                        _b(parent_id or ""), exp_blob, exp_meta, prev)
        if recomputed != entry_hash or not self.verifier.verify(entry_hash, sig):
            return False, "ledger entry signature invalid"
        if blob_hash != exp_blob:
            return False, "checkpoint content hash mismatch (tampered or replayed)"
        if meta_hash != exp_meta:
            return False, "metadata hash mismatch (tampered)"
        return True, "ok"

    def verify_writes(self, thread_id, ns, checkpoint_id, task_id, writes_hash) -> tuple[bool, str]:
        with self._lock:
            row = self.conn.execute(
                "SELECT writes_hash, entry_hash, signature FROM writes "
                "WHERE thread_id=? AND ns=? AND checkpoint_id=? AND task_id=?",
                (thread_id, ns, checkpoint_id, task_id),
            ).fetchone()
        if row is None:
            return False, "no ledger entry for pending writes"
        exp_hash, entry_hash, sig = row
        recomputed = _h(_b("writes"), _b(thread_id), _b(ns), _b(checkpoint_id), _b(task_id), exp_hash)
        if recomputed != entry_hash or not self.verifier.verify(entry_hash, sig):
            return False, "writes signature invalid"
        if writes_hash != exp_hash:
            return False, "pending-writes hash mismatch (tampered)"
        return True, "ok"

    def head(self, thread_id, ns) -> str | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT checkpoint_id, entry_hash, seq, signature FROM head WHERE thread_id=? AND ns=?",
                (thread_id, ns),
            ).fetchone()
        if row is None:
            return None
        checkpoint_id, entry_hash, seq, sig = row
        anchor = _h(_b("head"), _b(thread_id), _b(ns), _b(checkpoint_id), entry_hash, seq.to_bytes(8, "big"))
        if not self.verifier.verify(anchor, sig):
            return None
        return checkpoint_id

    def close(self) -> None:
        with self._lock:
            self.conn.close()
