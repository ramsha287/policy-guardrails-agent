"""User confirmation (outcome "verify"): response fields, client calls and the hook exception."""

import json

import httpx
import pytest

from guardrail_sdk import (
    GuardClient,
    GuardHooks,
    GuardrailBlocked,
    GuardrailEscalated,
    GuardrailVerificationRequired,
    GuardRequest,
    GuardResponse,
    SyncGuardClient,
)

INFO = {
    "id": "v1",
    "kind": "user_confirmation",
    "status": "pending",
    "expires_at": 1.0,
    "summary": "send x",
    "user_id": "u1",
}
VERIFY = {
    "request_id": "r", "trace_id": "t", "stage": "tool", "decision": "escalate", "reason": "user confirmation required",
    "risk_score": 60, "trust_score": 80, "payload": None, "policy": {"allow": True, "reason": "ok"},
    "outcome": "verify", "reason_codes": ["VERIFY_USER_CONFIRMATION"], "verification": INFO,
}  # fmt: skip


def test_verification_channels_are_left_out_unless_set():
    base = {"agent_id": "a", "action": "x", "payload": {"text": "hi"}}
    assert "verification_channels" not in GuardRequest.model_validate(base).model_dump(exclude_none=True)
    r = GuardRequest.model_validate({**base, "verification_channels": ["user_confirmation"]})
    assert r.model_dump(exclude_none=True)["verification_channels"] == ["user_confirmation"]
    assert GuardResponse.model_validate(VERIFY).verification.summary == "send x"


async def test_client_status_and_confirm():
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.path.endswith("/confirm"):
            return httpx.Response(200, json={**INFO, "status": "confirmed"})
        if req.url.path == "/v1/verifications/missing":
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json=INFO)

    g = GuardClient("http://gw", "k", agent_id="a", http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert (await g.verification_status("v1")).status == "pending"
    done = await g.confirm_verification("v1", "user-token", approve=True)
    assert done.status == "confirmed"
    assert seen[1].headers["Authorization"] == "Bearer user-token" and seen[1].headers["X-API-Key"] == "k"
    assert json.loads(seen[1].content) == {"approve": True}
    with pytest.raises(Exception, match="not found"):
        await g.verification_status("missing")


def test_sync_client_confirm():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["Authorization"] == "Bearer tok"
        return httpx.Response(200, json={**INFO, "status": "rejected"})

    c = SyncGuardClient("http://gw", "k", agent_id="a", http=httpx.Client(transport=httpx.MockTransport(handler)))
    assert c.confirm_verification("v1", "tok", approve=False).status == "rejected"


async def test_hooks_raise_verification_required():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json=VERIFY)

    g = GuardClient("http://gw", "k", agent_id="a", http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    hooks = GuardHooks(g)
    with pytest.raises(GuardrailVerificationRequired) as err:
        await hooks.before_llm("hi")
    assert isinstance(err.value, GuardrailBlocked) and not isinstance(err.value, GuardrailEscalated)
    assert err.value.verification is not None and err.value.verification.id == "v1"
