"""End-to-end: the sample agent against a guardrail gateway.

- Fake-gateway tests always run (wiring of the four stages).
- Live tests run against the docker compose stack when GUARDRAIL_E2E_URL and
  GUARDRAIL_E2E_KEY are set (dev snapshot, real Presidio):

    export GUARDRAIL_E2E_URL=http://localhost:8100
    export GUARDRAIL_E2E_KEY=$(docker compose exec -T guardrail-gateway \
        sh -c '. /bootstrap/dev.env; echo $DEMO_GATEWAY_API_KEY')
    pytest tests/e2e -v
"""

import os
import re

import httpx
import pytest

from examples.sample_agent.agent import SampleAgent
from guardrail_sdk import GuardClient, GuardHooks
from tests.fake_gateway import FakeGateway

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
LIVE_URL = os.environ.get("GUARDRAIL_E2E_URL")
LIVE_KEY = os.environ.get("GUARDRAIL_E2E_KEY")
live = pytest.mark.skipif(not (LIVE_URL and LIVE_KEY), reason="set GUARDRAIL_E2E_URL and GUARDRAIL_E2E_KEY")


def fake_agent() -> tuple[SampleAgent, FakeGateway]:
    gw = FakeGateway()
    http = httpx.AsyncClient(transport=httpx.MockTransport(gw))
    hooks = GuardHooks(GuardClient("http://gw", "k", agent_id="research-agent", http=http), data_classification="PII")
    return SampleAgent(hooks), gw


async def test_fake_all_stages_called_in_order():
    agent, gw = fake_agent()
    trace = await agent.ask("Summarise escalations for jane.doe@example.com")
    assert [r["stage"] for r in gw.requests] == ["input", "retrieval", "tool", "tool", "output"]
    assert not EMAIL.search(trace.llm_prompt) and not EMAIL.search(trace.answer)


async def test_fake_block_stops_before_the_model():
    agent, _ = fake_agent()
    trace = await agent.ask("BLOCKME")
    assert trace.blocked and trace.llm_prompt == ""


# ---- live stack --------------------------------------------------------------------------


@pytest.fixture
async def live_agent():
    async with GuardClient(LIVE_URL or "", LIVE_KEY or "", agent_id="research-agent") as client:
        yield SampleAgent(GuardHooks(client, user_id="e2e", data_classification="PII"))


@live
async def test_live_pii_never_reaches_the_model(live_agent):
    trace = await live_agent.ask("Summarise escalations and refunds for jane.doe@example.com")
    assert trace.blocked is None, trace.blocked
    assert not EMAIL.search(trace.llm_prompt), trace.llm_prompt  # input, retrieval and tool redacted
    assert not EMAIL.search(trace.answer)
    assert "[EMAIL_ADDRESS]" in trace.llm_prompt


@live
async def test_live_ssn_chunk_is_dropped(live_agent):
    trace = await live_agent.ask("What does the legacy customer record say?")
    assert trace.blocked is None, trace.blocked
    assert not any("536-90-4399" in t for t in trace.retrieved)


@live
async def test_live_ssn_in_prompt_is_blocked(live_agent):
    trace = await live_agent.ask("My SSN is 536-90-4399, update my record")
    assert trace.blocked and trace.blocked.startswith("input")


@live
async def test_live_pii_to_external_tool_is_blocked(live_agent):
    trace = await live_agent.ask("Please send my number +1 212 555 0199 to the partner")
    assert trace.blocked and trace.blocked.startswith("tool"), trace
