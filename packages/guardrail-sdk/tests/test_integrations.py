import inspect
from dataclasses import dataclass, field

import httpx
import pytest
from pydantic import BaseModel

from guardrail_sdk import GuardClient, GuardHooks, GuardrailBlocked, SyncGuardClient, SyncGuardHooks
from guardrail_sdk.integrations import guard_tool
from guardrail_sdk.integrations.crewai import guard_crewai_tool, guard_inputs, guard_output
from guardrail_sdk.integrations.langgraph import guard_retriever, input_guard_node, output_guard_node
from tests.fake_gateway import FakeGateway


def ahooks(gw=None):
    http = httpx.AsyncClient(transport=httpx.MockTransport(gw or FakeGateway()))
    return GuardHooks(GuardClient("http://gw", "k", agent_id="a", http=http))


def shooks(gw=None):
    http = httpx.Client(transport=httpx.MockTransport(gw or FakeGateway()))
    return SyncGuardHooks(SyncGuardClient("http://gw", "k", agent_id="a", http=http))


class Msg(BaseModel):
    """Shape of a langchain_core message: id, type, content, pydantic model_copy."""

    id: str
    type: str
    content: str


@dataclass
class Doc:
    page_content: str
    metadata: dict = field(default_factory=dict)


# ---- tools ------------------------------------------------------------------------------


async def test_guard_tool_async_keeps_signature():
    calls = []

    @guard_tool(ahooks(), name="crm.lookup")
    async def lookup(email: str, limit: int = 5) -> dict:
        """Look up a customer."""
        calls.append((email, limit))
        return {"owner": "boss@corp.com"}

    assert list(inspect.signature(lookup).parameters) == ["email", "limit"]
    assert lookup.__doc__ == "Look up a customer."
    assert await lookup("a@b.com") == {"owner": "[EMAIL]"}
    assert calls == [("[EMAIL]", 5)]  # the tool itself received redacted arguments


def test_guard_tool_sync_and_mismatch():
    @guard_tool(shooks())
    def echo(text: str) -> str:
        return text + " x@y.com"

    assert echo("hi") == "hi [EMAIL]"
    with pytest.raises(TypeError):
        guard_tool(ahooks())(lambda text: text)
    with pytest.raises(TypeError):

        @guard_tool(shooks())
        async def bad(x: str) -> str:
            return x


def test_guard_tool_policy_deny_stops_call():
    ran = []

    @guard_tool(shooks(), name="forbidden.shell")
    def shell(cmd: str) -> str:
        ran.append(cmd)
        return "ok"

    with pytest.raises(GuardrailBlocked):
        shell("rm -rf /")
    assert ran == []


# ---- LangGraph --------------------------------------------------------------------------


async def test_input_node_replaces_latest_human_message_by_id():
    node = input_guard_node(ahooks())
    state = {
        "messages": [
            Msg(id="1", type="system", content="sys a@b.com"),
            Msg(id="2", type="human", content="me: c@d.com"),
        ]
    }
    update = await node(state)
    assert update == {"messages": [Msg(id="2", type="human", content="me: [EMAIL]")]}


async def test_nodes_return_nothing_when_clean_and_handle_dicts():
    assert await input_guard_node(ahooks())({"messages": [Msg(id="1", type="human", content="hello")]}) == {}
    update = await output_guard_node(ahooks())({"messages": [{"role": "assistant", "content": "x@y.com", "id": "9"}]})
    assert update == {"messages": [{"role": "assistant", "content": "[EMAIL]", "id": "9"}]}


async def test_node_block_raises_by_default():
    with pytest.raises(GuardrailBlocked):
        await input_guard_node(ahooks())({"messages": [Msg(id="1", type="human", content="BLOCKME")]})


async def test_guard_retriever_maps_documents():
    async def retrieve(query: str):
        return [Doc("mail a@b.com", {"source": "kb"}), Doc("DROPME secret"), Doc("clean")]

    docs = await guard_retriever(ahooks(), retrieve)("q")
    assert [d.page_content for d in docs] == ["mail [EMAIL]", "clean"]
    assert docs[0].metadata == {"source": "kb"}


# ---- CrewAI -----------------------------------------------------------------------------


class FakeCrewTool(BaseModel):
    """Shape of a CrewAI BaseTool: pydantic model with name and _run."""

    name: str = "crm.lookup"

    def _run(self, email: str) -> str:
        return f"owner of {email} is boss@corp.com"


def test_guard_crewai_tool_wraps_run():
    tool = guard_crewai_tool(FakeCrewTool(), shooks())
    assert tool._run(email="a@b.com") == "owner of [EMAIL] is [EMAIL]"
    assert tool._run("a@b.com") == "owner of [EMAIL] is [EMAIL]"


def test_crewai_inputs_and_output():
    hooks = shooks()
    assert guard_inputs(hooks, {"q": "a@b.com", "n": 3, "blank": ""}) == {"q": "[EMAIL]", "n": 3, "blank": ""}

    class CrewOutput:
        raw = "answer for c@d.com"

    assert guard_output(hooks, CrewOutput()) == "answer for [EMAIL]"
