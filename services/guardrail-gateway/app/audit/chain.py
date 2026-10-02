"""Tamper evidence for decision records: one hash chain per (gateway process, tenant).

Every audit event gets `chain_id`, `chain_seq`, `prev_hash` and `record_hash`, where

    record_hash = sha256(canonical JSON of the event's key fields, including prev_hash)

and `prev_hash` is the previous record's hash in the same chain ("0" * 64 for the first). Editing,
deleting or reordering a record breaks the chain from that point on, and a missing sequence number
shows a gap. The table is already append-only (a trigger blocks UPDATE/DELETE); the chain also
catches changes made by someone who can bypass the trigger, e.g. with direct disk or superuser
access, when it is checked against a copy of the hashes kept elsewhere.

Chains are per process (a restart starts new chains), so replicas never contend for a lock. Within
a process, `stamp` runs synchronously in submit order, so the order is the order of decisions.
Partitions dropped by the 12-month retention remove the start of a chain; `verify` then starts
from the oldest remaining record and reports that, not an error.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

GENESIS = "0" * 64
CHAIN_FIELDS = (
    "id", "created_at", "tenant_id", "request_id", "stage", "agent_id", "decision", "outcome", "reason",
    "risk_score", "payload_sha256", "snapshot_version", "chain_id", "chain_seq", "prev_hash",
)  # fmt: skip


def _norm(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat(timespec="microseconds")
    return value


def record_digest(event: Mapping[str, Any]) -> str:
    data = {k: _norm(event.get(k)) for k in CHAIN_FIELDS}
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditChain:
    def __init__(self, chain_id: str | None = None) -> None:
        self.chain_id = chain_id or uuid.uuid4().hex
        self._heads: dict[str, tuple[int, str]] = {}

    def stamp(self, event: dict[str, Any]) -> None:
        tenant = str(event.get("tenant_id") or "")
        seq, prev = self._heads.get(tenant, (0, GENESIS))
        event["chain_id"] = self.chain_id
        event["chain_seq"] = seq + 1
        event["prev_hash"] = prev
        event["record_hash"] = record_digest(event)
        self._heads[tenant] = (seq + 1, event["record_hash"])

    def heads(self) -> dict[str, tuple[int, str]]:
        """tenant -> (last chain_seq, last record_hash): exported hourly so a copy lives elsewhere."""
        return dict(self._heads)


@dataclass
class ChainReport:
    chains: int = 0
    records: int = 0
    problems: list[str] | None = None

    @property
    def ok(self) -> bool:
        return not self.problems


class ChainVerifier:
    """Incremental check for rows sorted by (chain_id, tenant_id, chain_seq): constant memory, so
    the CLI can stream months of audit rows. Rows without a chain (pre-0002) are skipped."""

    def __init__(self) -> None:
        self.problems: list[str] = []
        self.report = ChainReport(problems=self.problems)
        self._key: tuple[str, str] | None = None
        self._prev_hash: str | None = None
        self._prev_seq: int | None = None

    def add(self, r: Mapping[str, Any]) -> None:
        if not r.get("chain_id"):
            return
        key = (str(r["chain_id"]), str(r["tenant_id"]))
        if key != self._key:
            self._key, self._prev_hash, self._prev_seq = key, None, None
            self.report.chains += 1
        self.report.records += 1
        seq = int(r["chain_seq"])
        where = f"chain {key[0][:12]} tenant {key[1]} seq {seq}"
        if record_digest(r) != r.get("record_hash"):
            self.problems.append(f"{where}: record changed (hash mismatch)")
        if self._prev_seq is None:
            if seq == 1 and r.get("prev_hash") != GENESIS:
                self.problems.append(f"{where}: first record does not start the chain")
        elif seq != self._prev_seq + 1:
            self.problems.append(f"{where}: {seq - self._prev_seq - 1} record(s) missing before this one")
        elif r.get("prev_hash") != self._prev_hash:
            self.problems.append(f"{where}: link to previous record broken")
        self._prev_hash, self._prev_seq = str(r.get("record_hash")), seq


def verify(rows: Iterable[Mapping[str, Any]]) -> ChainReport:
    """Check rows in any order (sorts in memory; use ChainVerifier for large, pre-sorted streams)."""
    v = ChainVerifier()
    keyed = [r for r in rows if r.get("chain_id")]
    for r in sorted(keyed, key=lambda r: (str(r["chain_id"]), str(r["tenant_id"]), int(r["chain_seq"]))):
        v.add(r)
    return v.report
