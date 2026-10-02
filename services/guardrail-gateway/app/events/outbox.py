"""Event envelopes for the transactional outbox (CloudEvents 1.0 structured JSON).

decision.made.v1     one per audit record, written in the same transaction as the record, so an
                     event exists if and only if the decision was recorded. Same rule as the audit
                     log: no payload text, only names, codes, scores and hashes.
audit.chain_heads.v1 hourly, the head (seq, hash) of every audit hash chain in this process. A
                     consumer that keeps them (SIEM, object storage with retention lock) can later
                     prove the audit table wasn't rewritten: `verify-audit-chain` must reach the
                     same hashes.

Consumers must tolerate duplicates (delivery is at least once; dedupe on `id`) and must not rely
on order across gateway replicas (within one chain, `chain_seq` gives the order).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

DECISION_TOPIC = "decision.made.v1"
CHAIN_HEADS_TOPIC = "audit.chain_heads.v1"

_DECISION_FIELDS = (
    "request_id", "trace_id", "stage", "environment", "agent_id", "user_id", "session_id", "action", "resource",
    "decision", "outcome", "reason_codes", "risk_score", "trust_score", "policy_allow", "assurance",
    "payload_sha256", "snapshot_version", "latency_ms", "chain_id", "chain_seq", "record_hash",
)  # fmt: skip


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
    if isinstance(value, str) and value:  # replayed from the disk spool
        return value
    return datetime.now(UTC).isoformat()


def envelope(*, topic: str, event_id: str, tenant_id: str, source: str, time: Any, subject: str | None,
             data: dict[str, Any]) -> dict[str, Any]:  # fmt: skip
    out = {
        "specversion": "1.0",
        "id": event_id,
        "source": source,
        "type": f"io.guardrail.{topic}",
        "time": _iso(time),
        "datacontenttype": "application/json",
        "tenantid": tenant_id,
        "data": data,
    }
    if subject:
        out["subject"] = subject
    return out


def decision_event(audit: Mapping[str, Any], source: str) -> dict[str, Any]:
    """The outbox row for one audit event (dict with event_id/topic/tenant_id/payload)."""
    data: dict[str, Any] = {k: _plain(audit.get(k)) for k in _DECISION_FIELDS}
    data["audit_id"] = str(audit.get("id"))
    risk = audit.get("risk") or {}
    if isinstance(risk, Mapping):
        data["risk_band"] = risk.get("band")
        data["risk_mode"] = risk.get("mode")
        data["would_outcome"] = risk.get("would_outcome")
    descriptor = audit.get("descriptor")
    if isinstance(descriptor, Mapping):
        data["descriptor"] = dict(descriptor)
    eid = str(audit.get("id") or uuid.uuid4())
    tenant = str(audit.get("tenant_id") or "")
    return {
        "event_id": uuid.UUID(eid),
        "topic": DECISION_TOPIC,
        "tenant_id": tenant,
        "payload": envelope(
            topic=DECISION_TOPIC,
            event_id=eid,
            tenant_id=tenant,
            source=source,
            time=audit.get("created_at"),
            subject=str(audit.get("agent_id") or "") or None,
            data=data,
        ),  # fmt: skip
    }


def chain_heads_events(heads: Mapping[tuple[str, str], tuple[int, str]], source: str) -> list[dict[str, Any]]:
    """heads: (chain_id, tenant) -> (chain_seq, record_hash) of committed records."""
    out = []
    now = datetime.now(UTC)
    for (chain_id, tenant), (seq, digest) in sorted(heads.items()):
        eid = str(uuid.uuid4())
        out.append(
            {
                "event_id": uuid.UUID(eid),
                "topic": CHAIN_HEADS_TOPIC,
                "tenant_id": tenant,
                "payload": envelope(
                    topic=CHAIN_HEADS_TOPIC,
                    event_id=eid,
                    tenant_id=tenant,
                    source=source,
                    time=now,
                    subject=chain_id,
                    data={"chain_id": chain_id, "chain_seq": seq, "record_hash": digest},
                ),  # fmt: skip
            }
        )
    return out


def _plain(v: Any) -> Any:
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, datetime):
        return _iso(v)
    if isinstance(v, tuple):
        return list(v)
    return v
