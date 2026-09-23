import httpx
import pytest

from guardrail_sdk import (
    GuardClient,
    GuardDefaults,
    GuardHooks,
    GuardrailBlocked,
    GuardrailEscalated,
    SyncGuardClient,
    SyncGuardHooks,
)
from tests.fake_gateway import FakeGateway


def hooks(gw, wait=0.0):
    http = httpx.AsyncClient(transport=httpx.MockTransport(gw))
    client = GuardClient("http://gw", "k", agent_id="a", http=http)
    return GuardHooks(client, GuardDefaults(wait_for_review_seconds=wait, review_poll_seconds=0.01)), client


async def test_escalation_raises_without_waiting():
    h, _ = hooks(FakeGateway())
    with pytest.raises(GuardrailEscalated) as e:
        await h.before_llm("ESCALATEME please")
    assert e.value.escalation_id == "esc-1"
    assert isinstance(e.value, GuardrailBlocked)  # callers that only catch GuardrailBlocked stay safe


async def test_wait_returns_held_payload_once_approved():
    gw = FakeGateway(["pending", "pending", "approved"])
    h, _ = hooks(gw, wait=5)
    assert await h.before_llm("ESCALATEME please") == "ESCALATEME please"
    assert gw.polls == 3


async def test_rejected_or_expired_blocks_with_reviewer_reason():
    for outcome in ("rejected", "expired"):
        h, _ = hooks(FakeGateway(["pending", outcome]), wait=5)
        with pytest.raises(GuardrailBlocked) as e:
            await h.before_llm("ESCALATEME")
        assert not isinstance(e.value, GuardrailEscalated) and outcome in e.value.reason


async def test_wait_times_out_still_pending():
    h, _ = hooks(FakeGateway(["pending"]), wait=0.05)
    with pytest.raises(GuardrailEscalated, match="still waiting"):
        await h.before_llm("ESCALATEME")


async def test_client_wait_for_escalation():
    gw = FakeGateway(["pending", "approved"])
    _, client = hooks(gw)
    resp = await client.check_input("ESCALATEME")
    assert resp.decision.value == "escalate" and resp.escalation_id == "esc-1" and resp.payload is None
    status = await client.wait_for_escalation("esc-1", timeout_seconds=5, poll_seconds=0.01)
    assert status.status == "approved" and status.payload["text"] == "ESCALATEME"


def test_sync_hooks_wait_for_review():
    gw = FakeGateway(["pending", "approved"])
    http = httpx.Client(transport=httpx.MockTransport(gw))
    h = SyncGuardHooks(
        SyncGuardClient("http://gw", "k", agent_id="a", http=http),
        GuardDefaults(wait_for_review_seconds=5, review_poll_seconds=0.01),
    )
    assert h.before_llm("ESCALATEME") == "ESCALATEME"
    h2 = SyncGuardHooks(SyncGuardClient("http://gw", "k", agent_id="a", http=http))
    with pytest.raises(GuardrailEscalated):
        h2.before_llm("ESCALATEME")
