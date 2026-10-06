"""Playground: the console relays a real agent request to the gateway's enforcement path."""

import json
from datetime import timedelta

import httpx
import pytest

from app.domain.rbac import Forbidden, Principal
from app.domain.records import utcnow
from app.errors import ValidationFailed
from app.services.catalog import CatalogService
from app.services.playground import PlaygroundService
from app.services.simulation import SimulationUnavailable
from guardrail_sdk.api import GuardRequest
from guardrail_sdk.models import Stage
from tests.helpers import ACME_ADMIN, ACME_REVIEWER, ALICE, EDITOR, VIEWER, make_ctx

GLOBEX_ADMIN = Principal("key-globex", "globex-admin", frozenset({"admin"}), tenant_id="globex")


class FakeGateway:
    def __init__(self, status=200, body=None):
        self.calls: list[httpx.Request] = []
        self.status = status
        self.body = body

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.url.path.startswith("/v1/escalations/"):
            return httpx.Response(200, json={"escalation_id": request.url.path.rsplit("/", 1)[1], "decision": "allow"})
        body = json.loads(request.content)
        return httpx.Response(
            self.status,
            json=self.body
            or {"request_id": "req-1", "decision": "modify", "outcome": "modify", "agent": body["agent_id"]},
        )


async def setup(environments=("dev",), status=200, body=None):
    ctx, store, _ = make_ctx()
    cat = CatalogService(ctx)
    for t in ("acme", "globex"):
        await cat.create_tenant(ALICE, t, t.title())
    key, raw = await cat.create_api_key(ALICE, "acme", "demo")
    gw = FakeGateway(status, body)
    svc = PlaygroundService(
        ctx,
        httpx.AsyncClient(transport=httpx.MockTransport(gw.handler)),
        environments=frozenset(environments),
        default_gateway_url="http://gw:8100/",
    )
    return svc, cat, store, gw, key, raw


def req(**over):
    return GuardRequest.model_validate(
        {"agent_id": "research-agent", "action": "llm.chat", "payload": {"text": "hello"}, **over}
    )


async def test_relays_a_real_request_with_the_agents_key_and_logs_who_sent_it():
    svc, _, store, gw, key, raw = await setup()
    out = await svc.send(EDITOR, environment="dev", stage=Stage.INPUT, gateway_key=raw, request=req())
    sent = gw.calls[0]
    assert str(sent.url) == "http://gw:8100/v1/guard/input" and sent.headers["X-API-Key"] == raw
    assert json.loads(sent.content)["agent_id"] == "research-agent"
    assert out["status"] == 200 and out["tenant_id"] == "acme" and out["response"]["decision"] == "modify"
    assert out["key"] == {"id": key.id, "name": "demo", "prefix": key.prefix, "agent_id": None}
    change = (await store.list_changes("playground", None, 10))[0]
    assert change.entity_id == "req-1" and change.after["decision"] == "modify" and change.after["stage"] == "input"
    assert raw not in json.dumps(change.model_dump(mode="json"))  # the key is never logged
    assert "hello" not in json.dumps(change.model_dump(mode="json"))  # nor the payload


async def test_gateway_status_codes_come_back_as_they_are():
    body = {"request_id": "r", "decision": "escalate", "outcome": "hold", "escalation_id": "esc-1"}
    svc, _, _, _, _, raw = await setup(status=202, body=body)
    out = await svc.send(ALICE, environment="dev", stage=Stage.TOOL, gateway_key=raw, request=req())
    assert out["status"] == 202 and out["response"]["escalation_id"] == "esc-1"
    polled = await svc.escalation(ALICE, environment="dev", gateway_key=raw, escalation_id="esc-1")
    assert polled["response"]["decision"] == "allow"
    with pytest.raises(ValidationFailed):
        await svc.escalation(ALICE, environment="dev", gateway_key=raw, escalation_id="../internal")


async def test_only_enabled_environments():
    svc, _, _, gw, _, raw = await setup(environments=("dev",))
    assert svc.enabled_environments() == ["dev"]
    with pytest.raises(Forbidden):
        await svc.send(ALICE, environment="production", stage=Stage.INPUT, gateway_key=raw, request=req())
    off, *_ = await setup(environments=())
    assert off.enabled_environments() == []
    assert gw.calls == []


async def test_who_may_send_and_with_which_key():
    svc, cat, _, gw, key, raw = await setup()
    for p in (VIEWER, ACME_REVIEWER, GLOBEX_ADMIN):  # no catalog:write on acme
        with pytest.raises(Forbidden):
            await svc.send(p, environment="dev", stage=Stage.INPUT, gateway_key=raw, request=req())
    await svc.send(ACME_ADMIN, environment="dev", stage=Stage.INPUT, gateway_key=raw, request=req())
    for bad in ("not-a-key", "gk_unknown"):
        with pytest.raises(ValidationFailed):
            await svc.send(ALICE, environment="dev", stage=Stage.INPUT, gateway_key=bad, request=req())
    with pytest.raises(ValidationFailed):
        await svc.send(ALICE, environment="dev", stage=Stage.AGENT, gateway_key=raw, request=req())
    _, staging_only = await cat.create_api_key(ALICE, "acme", "staging", environments=["staging"])
    with pytest.raises(ValidationFailed, match="not valid in dev"):
        await svc.send(ALICE, environment="dev", stage=Stage.INPUT, gateway_key=staging_only, request=req())
    _, old = await cat.create_api_key(ALICE, "acme", "old", expires_at=utcnow() - timedelta(minutes=1))
    with pytest.raises(ValidationFailed, match="expired"):
        await svc.send(ALICE, environment="dev", stage=Stage.INPUT, gateway_key=old, request=req())
    await cat.revoke_api_key(ALICE, "acme", key.id)
    with pytest.raises(ValidationFailed, match="revoked"):
        await svc.send(ALICE, environment="dev", stage=Stage.INPUT, gateway_key=raw, request=req())
    assert len(gw.calls) == 1  # nothing else reached the gateway


async def test_unreachable_gateway():
    ctx, _, _ = make_ctx()
    cat = CatalogService(ctx)
    await cat.create_tenant(ALICE, "acme", "Acme")
    _, raw = await cat.create_api_key(ALICE, "acme", "demo")

    def down(request):
        raise httpx.ConnectError("refused")

    svc = PlaygroundService(
        ctx, httpx.AsyncClient(transport=httpx.MockTransport(down)), environments=frozenset({"dev"}),
        default_gateway_url="http://gw:8100",
    )  # fmt: skip
    with pytest.raises(SimulationUnavailable) as exc:
        await svc.send(ALICE, environment="dev", stage=Stage.INPUT, gateway_key=raw, request=req())
    assert exc.value.status == 502
