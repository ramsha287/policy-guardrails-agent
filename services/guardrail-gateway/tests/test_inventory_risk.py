"""Inventory findings published in the catalog become capped risk signals (phase 9)."""

import asyncio
from types import SimpleNamespace

from app.context.builder import ContextBuilder
from app.context.catalog import ActionRule, AgentInfo, CachedCatalog, TenantCatalog
from app.engine.pipeline import GuardrailEngine
from app.engine.remote import GATEWAY_CAPABILITIES, CatalogHolder
from app.gateway.flow import run_stage
from app.risk.contextual import ContextualDecisions, tool_is_flagged
from app.session.store import MemorySessionStore
from guardrail_sdk import GuardRequest, Stage
from guardrail_sdk.documents import CatalogAgent, CatalogDoc, CatalogTenant
from tests.helpers import bind, snapshot
from tests.test_contextual_flow import BOUND, Audit, Policy


class Catalog:
    def __init__(self, findings=(), tools=frozenset()):
        self.findings, self.tools = tuple(findings), frozenset(tools)

    async def load(self, tenant_id):
        return TenantCatalog(
            agents={"research-agent": AgentInfo("research-agent", 80, ("*",), self.findings)},
            actions={
                "crm.create_ticket": [ActionRule("crm.create_ticket", "*", 20)],
                "llm.chat": [ActionRule("llm.chat", "*", 10)],
            },
            flagged_tools=self.tools,
        )


def services(catalog):
    return SimpleNamespace(
        snapshots=SimpleNamespace(current=snapshot(bind("noop", stages=("input", "retrieval", "tool", "output")))),
        contexts=ContextBuilder(CachedCatalog(catalog), "production"),
        policy=Policy(),
        engine=GuardrailEngine(escalate_as_block=True),
        audit=Audit(),
        control_plane=None,
        contextual=ContextualDecisions(MemorySessionStore(), mode="shadow"),
    )


TICKET = {
    "agent_id": "research-agent",
    "action": "crm.create_ticket",
    "session_id": "s1",
    "payload": {"tool_call": {"name": "crm-demo/create_ticket", "arguments": {"title": "printer jam"}}},
}


def risk(svc, body=TICKET, stage=Stage.TOOL):
    res = asyncio.run(
        run_stage(svc, BOUND, stage, GuardRequest.model_validate(body), request_id="r", trace_id="0" * 32)
    )
    return res.response.risk


def test_no_findings_no_signals():
    r = risk(services(Catalog()))
    assert not {"AGENT_FINDING", "TOOL_DEFINITION_CHANGED"} & {s.code for s in r.signals}


def test_open_agent_finding_adds_capped_points():
    base = risk(services(Catalog()))
    r = risk(services(Catalog(findings=["unmanaged_agent"])))
    sig = {s.code: s for s in r.signals}
    assert sig["AGENT_FINDING"].points == 20 and sig["AGENT_FINDING"].detail == "unmanaged_agent"
    assert r.score == min(100, base.score + 20)


def test_calling_a_changed_tool_is_a_signal():
    r = risk(services(Catalog(tools={"crm-demo/create_ticket"})))
    assert "TOOL_DEFINITION_CHANGED" in {s.code for s in r.signals}
    # only tool calls: a chat turn with the same catalog has no tool to match
    chat = {"agent_id": "research-agent", "action": "llm.chat", "session_id": "s1", "payload": {"text": "hi"}}
    assert "TOOL_DEFINITION_CHANGED" not in {
        s.code for s in risk(services(Catalog(tools={"crm-demo/create_ticket"})), chat, Stage.INPUT).signals
    }


def test_tool_names_match_across_namespacing():
    flagged = frozenset({"crm-demo/create_ticket"})
    for name in ("create_ticket", "crm-demo/create_ticket", "mcp__crm-demo__create_ticket", "crm_demo__create_ticket",
                 "crm-demo:create_ticket", "CREATE_TICKET"):  # fmt: skip
        assert tool_is_flagged(name, flagged), name
    # another server's tool of the same name, and other tools, are not flagged
    for name in ("catalog.create_ticket", "jira__create_ticket", "create_tickets", "bulk_create_ticket", "ticket"):
        assert not tool_is_flagged(name, flagged), name
    assert not tool_is_flagged("create_ticket", frozenset())
    host = frozenset({"mcp.example.com/lookup"})
    assert tool_is_flagged("mcp__mcp__lookup", host) and not tool_is_flagged("kb.lookup", host)


def test_the_catalog_carries_findings_and_older_documents_still_load():
    assert "inventory_risk_v1" in GATEWAY_CAPABILITIES
    holder = CatalogHolder("production")
    doc = CatalogDoc(
        version="v1",
        tenants=[
            CatalogTenant(
                id="demo",
                name="Demo",
                agents=[CatalogAgent(agent_id="a", base_trust_score=70, open_findings=["unmanaged_agent"])],
                flagged_tools=["crm-demo/create_ticket"],
            )
        ],
    )
    assert holder.apply(doc.model_dump(mode="json"))
    cat = asyncio.run(holder.load("demo"))
    assert cat.agent("a").open_findings == ("unmanaged_agent",) and cat.flagged_tools == frozenset(
        {"crm-demo/create_ticket"}
    )
    # empty fields stay out of the JSON, so the hash and older gateways are unaffected
    plain = CatalogTenant(id="demo", name="Demo", agents=[CatalogAgent(agent_id="a", base_trust_score=70)])
    dumped = plain.model_dump(mode="json")
    assert "flagged_tools" not in dumped and "open_findings" not in dumped["agents"][0]
