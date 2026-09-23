"""A stand-in for the guardrail gateway used by SDK tests (httpx.MockTransport handler).

Rules: emails are redacted everywhere; text containing BLOCKME is blocked (200); tools named
forbidden.* are denied by "policy" (403)."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def _redact(value: Any) -> tuple[Any, bool]:
    if isinstance(value, str):
        new = EMAIL.sub("[EMAIL]", value)
        return new, new != value
    if isinstance(value, dict):
        out, changed = {}, False
        for k, v in value.items():
            out[k], c = _redact(v)
            changed |= c
        return out, changed
    if isinstance(value, list):
        items = [_redact(v) for v in value]
        return [i[0] for i in items], any(i[1] for i in items)
    return value, False


class FakeGateway:
    """ESCALATEME in the payload -> 202 escalation; `review_outcomes` is the sequence of statuses
    GET /v1/escalations/{id} returns (last one repeats)."""

    def __init__(self, review_outcomes: list[str] | None = None) -> None:
        self.requests: list[dict[str, Any]] = []
        self.review_outcomes = review_outcomes or ["pending"]
        self.polls = 0
        self.held: dict[str, Any] = {}

    def _escalation(self, escalation_id: str) -> httpx.Response:
        status = self.review_outcomes[min(self.polls, len(self.review_outcomes) - 1)]
        self.polls += 1
        decision = {"pending": "escalate", "approved": "allow"}.get(status, "block")
        return httpx.Response(
            200,
            json={
                "escalation_id": escalation_id,
                "status": status,
                "decision": decision,
                "reason": f"{status} by reviewer",
                "reviewer": "rev" if status in ("approved", "rejected") else None,
                "payload": self.held.get(escalation_id) if status == "approved" else None,
            },
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "/v1/escalations/" in request.url.path:
            return self._escalation(request.url.path.rsplit("/", 1)[-1])
        body = json.loads(request.content)
        stage = request.url.path.rsplit("/", 1)[-1]
        self.requests.append({"stage": stage, **body})
        payload = body["payload"]
        base = {
            "request_id": "r",
            "trace_id": "a" * 32,
            "stage": stage,
            "risk_score": 10,
            "trust_score": 80,
            "policy": {"allow": True, "reason": "allowed", "obligations": []},
            "results": [],
        }
        tool = (payload.get("tool_call") or {}).get("name", "")
        if tool.startswith("forbidden."):
            deny = {
                **base,
                "decision": "block",
                "reason": f"policy denied: tool {tool}",
                "payload": None,
                "policy": {"allow": False, "reason": "not allowed", "obligations": []},
            }
            return httpx.Response(403, json=deny)
        if "ESCALATEME" in json.dumps(payload):
            self.held["esc-1"] = payload
            return httpx.Response(
                202,
                json={
                    **base,
                    "decision": "escalate",
                    "reason": "needs review",
                    "payload": None,
                    "escalation_id": "esc-1",
                },
            )
        if "BLOCKME" in json.dumps(payload):
            return httpx.Response(200, json={**base, "decision": "block", "reason": "blocked", "payload": None})
        if stage == "retrieval":
            payload = {**payload, "chunks": [c for c in payload["chunks"] if "DROPME" not in c["text"]]}
        safe, changed = _redact(payload)
        decision = "modify" if changed or stage == "retrieval" else "allow"
        return httpx.Response(200, json={**base, "decision": decision, "reason": decision, "payload": safe})
