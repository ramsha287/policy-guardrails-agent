"""POST /internal/simulate logic (app/engine/simulation.py), without FastAPI."""

from types import SimpleNamespace

import httpx
import pytest

from app.config import APP_DIR, Settings
from app.context.builder import ContextBuilder
from app.context.catalog import ActionRule, AgentInfo, CachedCatalog, TenantCatalog
from app.engine.registry import PluginRegistry
from app.engine.simulation import SimulateIn, SimulationError, simulate
from app.policy.opa import PolicyDecision
from guardrail_sdk import EnvSecretReader, PluginContext


class Catalog:
    async def load(self, tenant_id):
        return TenantCatalog(
            agents={"research-agent": AgentInfo("research-agent", 80, ("*",))},
            actions={"llm.chat": [ActionRule("llm.chat", "*", 10)]},
            modifiers={("environment", "production"): 25},
        )


class Policy:
    def __init__(self):
        self.inputs = []

    async def evaluate(self, policy_input):
        self.inputs.append(policy_input)
        return PolicyDecision(True, "allowed", [])


class Audit:
    def __init__(self):
        self.events = []

    def submit(self, event):
        self.events.append(event)


def services(env="dev", registry=True):
    reg = None
    if registry:
        reg = PluginRegistry([APP_DIR / "plugins"], PluginContext(http=httpx.AsyncClient(), secrets=EnvSecretReader()))
        reg.discover()
    return SimpleNamespace(  # the subset of Services that simulation uses
        settings=Settings(postgres_dsn="postgresql+asyncpg://unused/db", environment=env),
        contexts=ContextBuilder(CachedCatalog(Catalog()), env),
        policy=Policy(),
        audit=Audit(),
        registry=reg,
    )


def body(environment="dev", version="1.0.0", **over):
    raw = {
        "snapshot": {
            "version": "draft",
            "environment": environment,
            "assignments": [
                {
                    "id": "n",
                    "guardrail_id": "noop",
                    "guardrail_version": version,
                    "stages": ["input"],
                    "mode": "enforce",
                }
            ],
        },
        "tenant_id": "demo",
        "stage": "input",
        "request": {"agent_id": "research-agent", "action": "llm.chat", "payload": {"text": "hello"}},
    }
    raw.update(over)
    return SimulateIn.model_validate(raw)


async def test_simulates_same_environment():
    svc = services()
    out = await simulate(svc, body())
    assert out["decision"] == "allow" and out["results"][0]["guardrail_id"] == "noop"
    assert out["environment"] == out["simulated_on"] == "dev"
    assert out["payload"]["text"] == "hello"
    assert svc.audit.events == []


async def test_other_environment_is_simulated_as_that_environment():
    """Regression: a staging/production draft on a dev gateway used to fail with HTTP 422."""
    svc = services(env="dev")
    out = await simulate(svc, body(environment="production"))
    assert out["environment"] == "production" and out["simulated_on"] == "dev"
    assert out["risk_score"] == 35  # llm.chat 10 + production modifier 25
    assert svc.policy.inputs[0]["context"]["environment"] == "production"


async def test_errors_are_explained():
    with pytest.raises(SimulationError) as exc:
        await simulate(services(), body(version="9.9.9"))
    assert exc.value.status == 422 and "noop@9.9.9 is not installed" in exc.value.error

    with pytest.raises(SimulationError) as exc:
        await simulate(services(registry=False), body())
    assert exc.value.status == 503

    bad_catalog = body(catalog={"version": "c", "tenants": "nope"})
    with pytest.raises(SimulationError) as exc:
        await simulate(services(), bad_catalog)
    assert exc.value.status == 422 and exc.value.error.startswith("invalid catalog document")

    wrong_stage = body(request={"agent_id": "research-agent", "action": "llm.chat", "payload": {}})
    with pytest.raises(SimulationError) as exc:
        await simulate(services(), wrong_stage)
    assert exc.value.status == 422 and exc.value.error.startswith("invalid payload")


async def test_draft_catalog_is_used_when_given():
    catalog = {
        "version": "draft",
        "tenants": [
            {
                "id": "demo",
                "name": "Demo",
                "agents": [{"agent_id": "research-agent", "base_trust_score": 42}],
                "actions": [{"action": "llm.chat", "base_risk_score": 5}],
            }
        ],
    }
    out = await simulate(services(), body(catalog=catalog))
    assert out["trust_score"] == 42 and out["risk_score"] == 5
