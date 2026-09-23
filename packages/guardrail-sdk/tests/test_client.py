import json

import httpx
import pytest

from guardrail_sdk.client import GuardClient, GuardrailGatewayError

RESP = {
    "request_id": "r1",
    "trace_id": "a" * 32,
    "stage": "input",
    "decision": "modify",
    "reason": "redacted",
    "risk_score": 40,
    "trust_score": 80,
    "payload": {"text": "hi [EMAIL]"},
    "policy": {"allow": True, "reason": "allowed", "obligations": []},
    "results": [],
}


def client_returning(status: int, body: dict, seen: list | None = None) -> GuardClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, json=body)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return GuardClient("http://gw", "k", agent_id="a1", http=http)


async def test_check_input_modify():
    seen: list[httpx.Request] = []
    g = client_returning(200, RESP, seen)
    r = await g.check_input("hi me@x.com", user_id="u1")
    assert r.allowed and r.payload.text == "hi [EMAIL]"
    assert str(seen[0].url) == "http://gw/v1/guard/input"
    assert seen[0].headers["X-API-Key"] == "k"
    assert json.loads(seen[0].content)["agent_id"] == "a1"


async def test_policy_deny_is_a_response_not_an_error():
    body = dict(RESP, decision="block", payload=None, policy={"allow": False, "reason": "no", "obligations": []})
    r = await client_returning(403, body).check_output("x")
    assert not r.allowed


async def test_auth_error_raises():
    with pytest.raises(GuardrailGatewayError) as e:
        await client_returning(401, {"error": "bad key"}).check_input("x")
    assert e.value.status_code == 401
