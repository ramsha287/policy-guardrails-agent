import json

import httpx

from app.config import Settings
from app.context.builder import ContextBuilder
from app.context.catalog import ActionRule, AgentInfo, CachedCatalog, TenantCatalog
from app.engine.pipeline import GuardrailEngine
from app.gateway.auth import Authenticator, Principal, hash_key
from app.main import create_app
from app.policy.opa import PolicyDecision
from app.services import Services
from guardrail_sdk import Decision, GuardrailResult
from tests.helpers import bind, modify_text, snapshot

KEY = "gk_test_key"


class Keys:
    async def lookup(self, key_hash):
        if key_hash == hash_key(KEY):
            return Principal("k1", "demo", "test", frozenset({"guard:invoke"}))
        return None


class Catalog:
    async def load(self, tenant_id):
        return TenantCatalog(
            agents={"research-agent": AgentInfo("research-agent", 80, ("*",))},
            actions={"llm.chat": [ActionRule("llm.chat", "*", 10)]},
        )


class Policy:
    def __init__(self, decision=None):
        self.decision = decision or PolicyDecision(True, "allowed", [])
        self.inputs = []

    async def evaluate(self, policy_input):
        self.inputs.append(policy_input)
        return self.decision


class Audit:
    def __init__(self):
        self.events = []

    def submit(self, event):
        self.events.append(event)


class Snapshots:
    def __init__(self, current):
        self.current = current
        self.last_error = None

    @property
    def version(self):
        return self.current.version if self.current else None


def make_client(snap=..., policy=None, max_body=4096):
    settings = Settings(postgres_dsn="postgresql+asyncpg://unused/db", max_body_bytes=max_body)
    redact = bind(
        "ai-gateway-pii",
        modify_text(lambda t: t.replace("jane@example.com", "[EMAIL_ADDRESS]")),
        stages=("input", "output"),
    )
    services = Services(
        settings=settings,
        auth=Authenticator(Keys()),
        contexts=ContextBuilder(CachedCatalog(Catalog()), "dev"),
        policy=policy or Policy(),
        engine=GuardrailEngine(),
        snapshots=Snapshots(snapshot(redact) if snap is ... else snap),
        audit=Audit(),
    )
    app = create_app(settings, services)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw"), services


BODY = {
    "agent_id": "research-agent",
    "action": "llm.chat",
    "user_id": "u1",
    "payload": {"text": "email jane@example.com"},
}


async def test_modify_flow_and_audit_has_no_raw_text():
    client, svc = make_client()
    async with client:
        r = await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": KEY, "X-Request-ID": "req-42"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "modify"
    assert body["payload"]["text"] == "email [EMAIL_ADDRESS]"
    assert body["request_id"] == "req-42" and r.headers["x-request-id"] == "req-42"
    assert body["trust_score"] == 80 and body["risk_score"] >= 10
    assert body["snapshot_version"] == "test-1"
    event = svc.audit.events[0]
    assert event["decision"] == "modify" and event["tenant_id"] == "demo"
    assert "jane@example.com" not in json.dumps(event, default=str)
    assert len(event["payload_sha256"]) == 64


async def test_missing_or_bad_key_is_401():
    client, _ = make_client()
    async with client:
        assert (await client.post("/v1/guard/input", json=BODY)).status_code == 401
        assert (await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": "nope"})).status_code == 401


async def test_policy_deny_is_403_and_skips_guardrails():
    policy = Policy(PolicyDecision(False, "agent trust 10 is below 50 in production"))
    client, svc = make_client(policy=policy)
    async with client:
        r = await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": KEY})
    assert r.status_code == 403
    body = r.json()
    assert body["decision"] == "block" and body["payload"] is None and body["results"] == []
    assert "trust 10" in body["reason"]
    assert svc.audit.events[0]["policy_allow"] is False


async def test_policy_input_never_contains_payload_text():
    policy = Policy()
    client, _ = make_client(policy=policy)
    async with client:
        await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": KEY})
    assert "jane@example.com" not in json.dumps(policy.inputs[0])


async def test_obligation_enforced_through_api():
    policy = Policy(PolicyDecision(True, "allowed", ["some-missing-guardrail"]))
    client, _ = make_client(policy=policy)
    async with client:
        r = await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": KEY})
    assert r.status_code == 200 and r.json()["decision"] == "block"


async def test_invalid_payload_for_stage_is_422():
    client, _ = make_client()
    async with client:
        r = await client.post("/v1/guard/retrieval", json=BODY, headers={"X-API-Key": KEY})
    assert r.status_code == 422 and "chunks" in r.json()["error"]


async def test_unknown_stage_and_bad_body_are_422_without_echo():
    client, _ = make_client()
    async with client:
        r1 = await client.post("/v1/guard/nope", json=BODY, headers={"X-API-Key": KEY})
        bad = dict(BODY, agent_id="")
        r2 = await client.post("/v1/guard/input", json=bad, headers={"X-API-Key": KEY})
    assert r1.status_code == 422 and r2.status_code == 422
    assert "jane" not in r2.text


async def test_body_limit_is_413():
    client, _ = make_client(max_body=200)
    big = dict(BODY, payload={"text": "x" * 500})
    async with client:
        r = await client.post("/v1/guard/input", json=big, headers={"X-API-Key": KEY})
    assert r.status_code == 413


async def test_no_snapshot_is_503():
    client, _ = make_client(snap=None)
    async with client:
        r = await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": KEY})
        ready = await client.get("/ready")
    assert r.status_code == 503 and ready.status_code == 503


async def test_ops_endpoints():
    client, _ = make_client()
    async with client:
        assert (await client.get("/health")).json() == {"status": "ok"}
        assert (await client.get("/ready")).status_code == 200
        assert (await client.get("/version")).json()["snapshot_version"] == "test-1"
        metrics = await client.get("/metrics")
    assert "guardrail_requests_total" in metrics.text


async def test_block_from_guardrail_is_200_with_no_payload():
    blocker = bind("ai-gateway-pii", lambda c, p: GuardrailResult(decision=Decision.BLOCK, reason="SSN", risk_score=90))
    client, _ = make_client(snap=snapshot(blocker))
    async with client:
        r = await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": KEY})
    assert r.status_code == 200
    assert r.json()["decision"] == "block" and r.json()["payload"] is None and r.json()["risk_score"] == 90
