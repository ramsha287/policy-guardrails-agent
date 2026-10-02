"""Outbox envelopes and sinks (the relay's SQL is covered by tests/integration/test_postgres.py)."""

import asyncio
import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime

import httpx
import pytest

from app.audit.chain import AuditChain
from app.events.outbox import CHAIN_HEADS_TOPIC, DECISION_TOPIC, chain_heads_events, decision_event
from app.events.sinks import RedisSink, WebhookSink, sign

AUDIT = {
    "id": uuid.UUID("00000000-0000-0000-0000-000000000001"),
    "created_at": datetime(2026, 10, 2, 12, 0, tzinfo=UTC),
    "tenant_id": "demo",
    "request_id": "r1",
    "agent_id": "research-agent",
    "stage": "tool",
    "decision": "allow",
    "outcome": "allow",
    "reason": "ok, contains jane@example.com",  # free text is NOT copied into events
    "reason_codes": ["NEW_SESSION"],
    "risk": {"band": "low", "mode": "shadow", "would_outcome": "allow", "signals": []},
    "descriptor": {"kind": "sql", "tables": ["public.customers"]},
    "chain_id": "c1",
    "chain_seq": 7,
    "record_hash": "ab" * 32,
    "payload_sha256": "0" * 64,
}


def test_decision_event_is_a_cloudevent_without_free_text():
    row = decision_event(AUDIT, "guardrail-gateway/gw-1")
    assert row["topic"] == DECISION_TOPIC and row["tenant_id"] == "demo" and row["event_id"] == AUDIT["id"]
    ev = row["payload"]
    assert ev["specversion"] == "1.0" and ev["id"] == str(AUDIT["id"]) and ev["type"] == "io.guardrail.decision.made.v1"
    assert ev["time"].startswith("2026-10-02T12:00") and ev["subject"] == "research-agent"
    data = ev["data"]
    assert data["record_hash"] == "ab" * 32 and data["risk_band"] == "low" and data["descriptor"]["kind"] == "sql"
    assert "jane@example.com" not in json.dumps(ev)
    json.dumps(row["payload"])  # serialisable as stored (JSONB)


def test_spooled_events_keep_their_ids_and_times():
    replayed = {**AUDIT, "id": str(AUDIT["id"]), "created_at": "2026-10-02T12:00:00+00:00"}
    row = decision_event(replayed, "gw")
    assert row["event_id"] == AUDIT["id"] and row["payload"]["time"] == "2026-10-02T12:00:00+00:00"


def test_chain_heads_events():
    chain = AuditChain("c1")
    e = {"tenant_id": "demo", "id": "x"}
    chain.stamp(e)
    rows = chain_heads_events({("c1", "demo"): (e["chain_seq"], e["record_hash"])}, "gw")
    assert len(rows) == 1 and rows[0]["topic"] == CHAIN_HEADS_TOPIC
    assert rows[0]["payload"]["data"] == {"chain_id": "c1", "chain_seq": 1, "record_hash": e["record_hash"]}


def test_webhook_sink_signs_the_batch_and_fails_on_non_2xx():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200 if len(seen) == 1 else 500)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            sink = WebhookSink(http, "https://siem.example/hook", "whsec", clock=lambda: 1_700_000_000)
            await sink.publish([{"id": "1"}])
            with pytest.raises(RuntimeError, match="500"):
                await sink.publish([{"id": "2"}])

    asyncio.run(go())
    req = seen[0]
    body = req.content
    assert json.loads(body) == [{"id": "1"}]
    assert req.headers["content-type"] == "application/cloudevents-batch+json"
    ts = req.headers["x-guardrail-timestamp"]
    expected = hmac.new(b"whsec", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert req.headers["x-guardrail-signature"] == f"sha256={expected}" == sign("whsec", ts, body)


def test_redis_sink_publishes_per_topic():
    published = []

    class Pipe:
        def publish(self, channel, msg):
            published.append((channel, json.loads(msg)))

        async def execute(self):
            return [1] * len(published)

    class R:
        def pipeline(self, transaction=False):
            return Pipe()

    asyncio.run(RedisSink(R()).publish([decision_event(AUDIT, "gw")["payload"]]))
    assert published[0][0] == "events.decision.made.v1" and published[0][1]["tenantid"] == "demo"
