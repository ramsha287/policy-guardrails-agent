"""Control plane -> gateway simulation: gateway routing per environment and error reporting."""

import json

import httpx
import pytest

from app.domain.rbac import Forbidden
from app.errors import NotFound, ValidationFailed
from app.services.assignments import AssignmentService
from app.services.catalog import CatalogService
from app.services.registry import RegistryService
from app.services.simulation import SimulationService, SimulationUnavailable
from guardrail_sdk.api import GuardRequest
from guardrail_sdk.models import Stage
from tests.helpers import ACME_REVIEWER, ALICE, EDITOR, NOOP, PII_11, make_ctx

REQUEST = GuardRequest.model_validate({"agent_id": "bot", "action": "llm.chat", "payload": {"text": "hi"}})
NOOP_ASSIGNMENT = {"id": "n", "guardrail_id": "noop", "guardrail_version": "1.0.0", "stages": ["input"]}


def gateway(status=200, body=None, seen=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append((str(request.url), json.loads(request.content), request.headers.get("x-internal-token")))
        env = json.loads(request.content)["snapshot"]["environment"]
        default = {"simulated": True, "environment": env, "simulated_on": "dev", "decision": "allow"}
        return httpx.Response(status, json=body if body is not None else default)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def setup(http, **urls):
    ctx, store, _ = make_ctx()
    reg, cat = RegistryService(ctx), CatalogService(ctx)
    for m in (PII_11, NOOP):
        await reg.register(ALICE, m)
    await cat.create_tenant(ALICE, "acme", "Acme")
    for env in ("dev", "staging"):
        await AssignmentService(ctx).put(EDITOR, env, NOOP_ASSIGNMENT)
    sim = SimulationService(
        ctx, reg, cat, http, "t" * 32, gateway_urls=urls.get("per_env"), default_gateway_url=urls.get("default")
    )
    return sim


async def run(sim, principal=ALICE, environment="staging", source="working", tenant="acme"):
    return await sim.run(
        principal, environment=environment, source=source, tenant_id=tenant, stage=Stage.INPUT, request=REQUEST
    )


async def test_routes_to_the_environment_gateway_and_falls_back_to_default():
    seen: list = []
    sim = await setup(gateway(seen=seen), per_env={"staging": "http://gw-staging:8100/"}, default="http://gw-dev:8100")
    out = await run(sim, environment="staging")
    await run(sim, environment="dev")
    assert seen[0][0] == "http://gw-staging:8100/internal/simulate" and seen[0][2] == "t" * 32
    assert seen[1][0] == "http://gw-dev:8100/internal/simulate"
    assert seen[0][1]["snapshot"]["environment"] == "staging" and seen[0][1]["catalog"]["tenants"][0]["id"] == "acme"
    assert out["snapshot"] == "draft" and out["result"]["decision"] == "allow"
    # the fake answers as a dev gateway, so the staging run carries a warning
    assert any("dev gateway" in w for w in out["warnings"])


async def test_gateway_error_detail_is_passed_through():
    sim = await setup(
        gateway(422, {"error": "snapshot does not compile on this gateway: noop@1.0.0 missing"}), default="http://gw"
    )
    with pytest.raises(ValidationFailed) as exc:
        await run(sim)
    assert "noop@1.0.0 missing" in str(exc.value)

    sim = await setup(gateway(500, {"error": "boom"}), default="http://gw")
    with pytest.raises(SimulationUnavailable) as exc2:
        await run(sim)
    assert exc2.value.status == 502 and "HTTP 500: boom" in str(exc2.value)


async def test_unreachable_or_unconfigured_gateway():
    def down(request):
        raise httpx.ConnectError("refused")

    sim = await setup(httpx.AsyncClient(transport=httpx.MockTransport(down)), default="http://gw")
    with pytest.raises(SimulationUnavailable) as exc:
        await run(sim)
    assert exc.value.status == 502 and "unreachable" in str(exc.value)

    sim = await setup(gateway())
    with pytest.raises(SimulationUnavailable) as exc:
        await run(sim)
    assert exc.value.status == 503


async def test_validation_before_calling_the_gateway():
    seen: list = []
    sim = await setup(gateway(seen=seen), default="http://gw")
    with pytest.raises(NotFound):
        await run(sim, tenant="nobody")
    with pytest.raises(NotFound):
        await run(sim, source="current")  # nothing published yet
    with pytest.raises(Forbidden):
        await run(sim, principal=ACME_REVIEWER, tenant="other")
    bad = {"id": "bad", "guardrail_id": "ai-gateway-pii", "guardrail_version": "1.1.0", "stages": ["input"]}
    await AssignmentService(sim.ctx).put(EDITOR, "staging", {**bad, "config": {}})  # project_id missing
    with pytest.raises(ValidationFailed) as exc:
        await run(sim)
    assert exc.value.errors
    assert seen == []
