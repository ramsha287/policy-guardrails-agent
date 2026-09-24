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


# ---- control-plane mode: escalation + simulate -----------------------------------------------

from app.config import APP_DIR  # noqa: E402
from app.engine.registry import PluginRegistry  # noqa: E402
from app.engine.remote import ControlPlaneClient  # noqa: E402
from guardrail_sdk import EnvSecretReader, PluginContext  # noqa: E402
from tests.helpers import result  # noqa: E402

TOKEN = "internal-token-0123456789"


def cp_client(handler):
    return ControlPlaneClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)), "http://cp", TOKEN)


def cp_mode_client(cp_handler, snap=None):
    settings = Settings(postgres_dsn="postgresql+asyncpg://unused/db", internal_token=TOKEN)
    registry = PluginRegistry([APP_DIR / "plugins"], PluginContext(http=httpx.AsyncClient(), secrets=EnvSecretReader()))
    registry.discover()
    services = Services(
        settings=settings,
        auth=Authenticator(Keys()),
        contexts=ContextBuilder(CachedCatalog(Catalog()), "dev"),
        policy=Policy(),
        engine=GuardrailEngine(escalate_as_block=False),
        snapshots=Snapshots(snap or snapshot(bind("human-check", result("escalate", "needs a human", 70)))),
        audit=Audit(),
        registry=registry,
        control_plane=cp_client(cp_handler),
    )
    app = create_app(settings, services)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw"), services


def fake_cp(status="approved"):
    held = {}

    def handler(request):
        if request.method == "POST":
            held["payload"] = json.loads(request.content)["payload"]
            return httpx.Response(201, json={"escalation_id": "rev-1", "expires_at": "x"})
        return httpx.Response(
            200,
            json={
                "escalation_id": "rev-1",
                "status": status,
                "decision": {"approved": "allow", "pending": "escalate"}.get(status, "block"),
                "reason": status,
                "payload": held.get("payload") if status == "approved" else None,
            },
        )

    return handler


async def test_escalation_is_202_then_released_after_approval():
    client, svc = cp_mode_client(fake_cp("approved"))
    async with client:
        r = await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": KEY})
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["decision"] == "escalate" and body["escalation_id"] == "rev-1" and body["payload"] is None
        s = await client.get("/v1/escalations/rev-1", headers={"X-API-Key": KEY})
    assert s.status_code == 200
    status = s.json()
    assert status["decision"] == "allow" and status["payload"]["text"] == "email jane@example.com"
    assert "stage" not in status["payload"]
    assert svc.audit.events[0]["decision"] == "escalate" and "rev-1" in svc.audit.events[0]["reason"]


async def test_escalation_blocks_when_review_queue_down():
    def down(request):
        raise httpx.ConnectError("down")

    client, _ = cp_mode_client(down)
    async with client:
        r = await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": KEY})
    assert r.status_code == 200 and r.json()["decision"] == "block" and "unavailable" in r.json()["reason"]


async def test_escalation_status_requires_key_and_file_mode_404():
    client, _ = cp_mode_client(fake_cp("pending"))
    async with client:
        assert (await client.get("/v1/escalations/rev-1")).status_code == 401
        pending = (await client.get("/v1/escalations/rev-1", headers={"X-API-Key": KEY})).json()
    assert pending["decision"] == "escalate" and pending["payload"] is None
    file_client, _ = make_client()
    async with file_client:
        assert (await file_client.get("/v1/escalations/x", headers={"X-API-Key": KEY})).status_code == 404


async def test_internal_simulate():
    client, svc = cp_mode_client(fake_cp())
    body = {
        "snapshot": {
            "version": "draft",
            "environment": "dev",
            "assignments": [
                {
                    "id": "n",
                    "guardrail_id": "noop",
                    "guardrail_version": "1.0.0",
                    "stages": ["input"],
                    "mode": "enforce",
                }
            ],
        },
        "catalog": None,
        "tenant_id": "demo",
        "stage": "input",
        "request": BODY,
    }
    async with client:
        assert (await client.post("/internal/simulate", json=body)).status_code == 401
        r = await client.post("/internal/simulate", json=body, headers={"X-Internal-Token": TOKEN})
        bad = {
            **body,
            "snapshot": {
                **body["snapshot"],
                "assignments": [{**body["snapshot"]["assignments"][0], "guardrail_version": "9.9.9"}],
            },
        }
        r_bad = await client.post("/internal/simulate", json=bad, headers={"X-Internal-Token": TOKEN})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["simulated"] is True and out["decision"] == "allow" and out["results"][0]["guardrail_id"] == "noop"
    assert r_bad.status_code == 422
    assert svc.audit.events == []  # simulations are never audited


async def test_rate_limit_is_429_with_retry_after():
    from app.gateway.ratelimit import RateLimiter

    client, svc = make_client()
    svc.limiter = RateLimiter(2)
    async with client:
        codes = [
            (await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": KEY})).status_code for _ in range(3)
        ]
        r = await client.post("/v1/guard/input", json=BODY, headers={"X-API-Key": KEY})
    assert codes == [200, 200, 429] and r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert len(svc.audit.events) == 2  # refused requests are not evaluated or audited


async def test_proxy_route_auth_and_disabled_state():
    from app.gateway.proxy import ChatProxy, ProxyConfig
    from tests.helpers import result

    client, svc = make_client(snap=snapshot(bind("allow-all", result("allow"), stages=("input", "output"))))
    body = {"model": "m", "messages": [{"role": "user", "content": "email jane@example.com"}]}
    async with client:
        off = await client.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {KEY}"})
        upstream = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "done"}}]})
            )
        )
        svc.proxy = ChatProxy(svc, ProxyConfig(upstream_url="https://llm.example/v1"), upstream)
        bad = await client.post("/v1/chat/completions", json=body, headers={"Authorization": "Bearer nope"})
        ok = await client.post(
            "/v1/chat/completions",
            json=body,
            headers={"Authorization": f"Bearer {KEY}", "X-Agent-Id": "research-agent"},
        )
    assert off.status_code == 404 and off.json()["error"]["type"] == "not_found"
    assert bad.status_code == 401 and bad.json()["error"]["type"] == "invalid_api_key"
    assert ok.status_code == 200, ok.text
    assert ok.json()["choices"][0]["message"]["content"] == "done"
    assert ok.headers["x-guardrail-input-decision"] == "allow"
    assert ok.headers["x-guardrail-output-decision"] == "allow"
