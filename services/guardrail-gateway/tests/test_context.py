from app.context.builder import ContextBuilder
from app.context.catalog import ActionRule, AgentInfo, CachedCatalog, TenantCatalog
from app.gateway.auth import Principal
from guardrail_sdk import GuardPayloadIn, GuardRequest, Stage

CAT = TenantCatalog(
    agents={"research-agent": AgentInfo("research-agent", 80, ("*",))},
    actions={
        "database.read": [
            ActionRule("database.read", "*", 30),
            ActionRule("database.read", "customer_*", 35),
            ActionRule("database.read", "customer_db", 40),
        ],
        "llm.chat": [ActionRule("llm.chat", "*", 10)],
    },
    modifiers={("classification", "PII"): 20, ("environment", "production"): 10},
)


class Store:
    calls = 0

    async def load(self, tenant_id):
        Store.calls += 1
        return CAT


PRINCIPAL = Principal("k1", "demo", "key", frozenset({"guard:invoke"}))


def req(**over):
    base = dict(
        agent_id="research-agent", action="database.read", resource="customer_db", payload=GuardPayloadIn(text="x")
    )
    base.update(over)
    return GuardRequest(**base)


async def build(env="dev", **over):
    b = ContextBuilder(CachedCatalog(Store(), ttl_seconds=60), env)
    return await b.build(principal=PRINCIPAL, req=req(**over), request_id="r", trace_id="t" * 32)


async def test_known_agent_and_exact_resource():
    built = await build()
    assert built.context.trust_score == 80
    assert built.context.risk_score == 40  # exact pattern beats customer_* and *
    assert built.context.tenant_id == "demo" and built.action_known


async def test_prefix_and_wildcard_matching():
    assert (await build(resource="customer_archive")).context.risk_score == 35
    assert (await build(resource="orders")).context.risk_score == 30


async def test_modifiers_add_and_cap():
    built = await build(env="production", data_classification="PII")
    assert built.context.risk_score == 70  # 40 + 20 + 10
    assert built.context.environment == "production"


async def test_unknown_agent_and_action():
    built = await build(agent_id="stranger", action="shell.exec")
    assert built.context.trust_score == 0
    assert built.context.risk_score == 100
    assert built.agent is None and not built.action_known


async def test_policy_input_excludes_arguments_and_payload():
    built = await build(arguments={"query": "select * from customers where email='a@b.c'"})
    doc = built.policy_input(Stage.TOOL, "database.read")
    assert "arguments" not in doc["context"]
    assert doc["agent"] == {"known": True, "allowed_tools": ["*"]}
    assert doc["tool_name"] == "database.read" and doc["stage"] == "tool"


async def test_catalog_is_cached():
    Store.calls = 0
    cache = CachedCatalog(Store(), ttl_seconds=60)
    await cache.get("demo")
    await cache.get("demo")
    assert Store.calls == 1
