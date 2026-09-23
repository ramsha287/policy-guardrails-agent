import httpx
import pytest

from guardrail_sdk import Chunk, GuardClient, GuardHooks, GuardrailBlocked, Message, SyncGuardClient, SyncGuardHooks
from tests.fake_gateway import FakeGateway


def async_hooks(gw: FakeGateway, **kw) -> GuardHooks:
    http = httpx.AsyncClient(transport=httpx.MockTransport(gw))
    return GuardHooks(GuardClient("http://gw", "k", agent_id="agent-1", http=http), **kw)


def sync_hooks(gw: FakeGateway, **kw) -> SyncGuardHooks:
    http = httpx.Client(transport=httpx.MockTransport(gw))
    return SyncGuardHooks(SyncGuardClient("http://gw", "k", agent_id="agent-1", http=http), **kw)


async def test_before_and_after_llm():
    gw = FakeGateway()
    hooks = async_hooks(gw, user_id="u1", data_classification="PII")
    assert await hooks.before_llm("mail a@b.com") == "mail [EMAIL]"
    assert await hooks.after_llm("reply to c@d.com") == "reply to [EMAIL]"
    assert gw.requests[0]["stage"] == "input" and gw.requests[1]["stage"] == "output"
    assert gw.requests[0]["user_id"] == "u1" and gw.requests[0]["data_classification"] == "PII"
    assert gw.requests[0]["action"] == "llm.chat" and gw.requests[0]["agent_id"] == "agent-1"


async def test_messages_keep_their_type():
    hooks = async_hooks(FakeGateway())
    as_models = await hooks.before_llm([Message(role="user", content="x@y.com")])
    assert isinstance(as_models[0], Message) and as_models[0].content == "[EMAIL]"
    as_dicts = await hooks.before_llm([{"role": "user", "content": "x@y.com"}])
    assert as_dicts == [{"role": "user", "content": "[EMAIL]"}]


async def test_block_raises_with_reason():
    hooks = async_hooks(FakeGateway())
    with pytest.raises(GuardrailBlocked) as e:
        await hooks.before_llm("BLOCKME please")
    assert e.value.reason == "blocked" and e.value.response.stage.value == "input"


async def test_retrieval_can_drop_and_redact():
    hooks = async_hooks(FakeGateway())
    out = await hooks.on_retrieval(
        [Chunk(id="1", text="a@b.com"), Chunk(id="2", text="DROPME"), Chunk(id="3", text="ok")]
    )
    assert [(c.id, c.text) for c in out] == [("1", "[EMAIL]"), ("3", "ok")]
    assert await hooks.on_retrieval([]) == []


async def test_tool_before_and_after():
    gw = FakeGateway()
    hooks = async_hooks(gw)
    args = await hooks.before_tool("crm.lookup", {"email": "a@b.com"})
    assert args == {"email": "[EMAIL]"}
    result = await hooks.after_tool("crm.lookup", args, {"owner": "o@p.com"})
    assert result == {"owner": "[EMAIL]"}
    assert gw.requests[0]["action"] == "crm.lookup"
    with pytest.raises(GuardrailBlocked, match="policy denied"):
        await hooks.before_tool("forbidden.shell", {"cmd": "ls"})


async def test_with_context_overrides_per_request():
    gw = FakeGateway()
    base = async_hooks(gw, user_id="u1")
    await base.with_context(user_id="u2", session_id="s9").before_llm("hi")
    assert gw.requests[0]["user_id"] == "u2" and gw.requests[0]["session_id"] == "s9"


def test_sync_hooks_mirror_async():
    gw = FakeGateway()
    hooks = sync_hooks(gw)
    assert hooks.before_llm("a@b.com") == "[EMAIL]"
    assert hooks.after_llm("c@d.com") == "[EMAIL]"
    assert [c.text for c in hooks.on_retrieval([Chunk(id="1", text="e@f.com")])] == ["[EMAIL]"]
    assert hooks.before_tool("t", {"x": "g@h.com"}) == {"x": "[EMAIL]"}
    assert hooks.after_tool("t", {}, "i@j.com") == "[EMAIL]"
    with pytest.raises(GuardrailBlocked):
        hooks.before_llm("BLOCKME")
