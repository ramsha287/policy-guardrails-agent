"""HTTP layer: auth, error mapping, two-person publish, ETag fetch, reviews, simulate."""

import httpx
import pytest
from cryptography.fernet import Fernet

from app.api.container import Container
from app.config import Settings
from app.domain.crypto import PayloadCipher
from app.events import MemoryPublisher
from app.main import create_app
from app.services.admin import AdminKeyService
from app.services.context import Ctx, Policy
from app.store.memory import MemoryStore
from tests.helpers import NOOP, PII_11, pii_assignment

TOKEN = "internal-token-0123456789"
BASE = "/cp/v1"


class Env:
    def __init__(self, gateway_handler=None):
        self.store = MemoryStore()
        ctx = Ctx(
            store=self.store,
            events=MemoryPublisher(),
            cipher=PayloadCipher(Fernet.generate_key().decode()),
            policy=Policy(),
        )
        gw_http = httpx.AsyncClient(transport=httpx.MockTransport(gateway_handler or (lambda r: httpx.Response(500))))
        self.container = Container(ctx=ctx, internal_token=TOKEN, http=gw_http, gateway_url="http://gw:8100")
        settings = Settings(postgres_dsn="postgresql+asyncpg://unused/db", internal_token=TOKEN)
        self.app = create_app(settings, self.container)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://cp")

    async def keys(self):
        svc = AdminKeyService(self.container.ctx)
        _, alice = await svc.create(None, "alice", ["admin"])
        _, bob = await svc.create(None, "bob", ["admin"])
        _, viewer = await svc.create(None, "viewer", ["viewer"])
        return {"X-Admin-Key": alice}, {"X-Admin-Key": bob}, {"X-Admin-Key": viewer}


@pytest.fixture
def env():
    return Env()


async def seed(env, alice):
    c = env.client
    for m in (PII_11, NOOP):
        assert (await c.post(f"{BASE}/guardrails/versions", json={"manifest": m}, headers=alice)).status_code == 201
    r = await c.put(f"{BASE}/environments/production/assignments/global-pii", json=pii_assignment(), headers=alice)
    assert r.status_code == 200, r.text


async def test_auth_required(env):
    r = await env.client.get(f"{BASE}/tenants")
    assert r.status_code == 401
    r = await env.client.get(f"{BASE}/internal/catalog")
    assert r.status_code == 401
    r = await env.client.get(f"{BASE}/internal/catalog", headers={"X-Internal-Token": "wrong-token-000000"})
    assert r.status_code == 401


async def test_tenant_and_keys(env):
    alice, _, viewer = await env.keys()
    c = env.client
    assert (await c.post(f"{BASE}/tenants", json={"id": "acme", "name": "Acme"}, headers=alice)).status_code == 201
    assert (await c.post(f"{BASE}/tenants", json={"id": "acme", "name": "dup"}, headers=alice)).status_code == 409
    assert (await c.post(f"{BASE}/tenants", json={"id": "x", "name": "no"}, headers=viewer)).status_code in (403, 422)
    created = (await c.post(f"{BASE}/tenants/acme/api-keys", json={"name": "bot"}, headers=alice)).json()
    assert created["key"].startswith("gk_") and "key_hash" not in created
    listed = (await c.get(f"{BASE}/tenants/acme/api-keys", headers=viewer)).json()
    assert "key" not in listed[0] and "key_hash" not in listed[0]
    r = await c.put(f"{BASE}/tenants/acme/agents/bot", json={"base_trust_score": 120}, headers=alice)
    assert r.status_code == 422
    r = await c.put(f"{BASE}/tenants/nope/agents/bot", json={"base_trust_score": 50}, headers=alice)
    assert r.status_code == 404


async def test_two_person_publish_over_http(env):
    alice, bob, _ = await env.keys()
    await seed(env, alice)
    c = env.client
    out = (await c.post(f"{BASE}/environments/production/publish", json={"note": "go"}, headers=alice)).json()
    assert out["status"] == "pending_approval"
    req_id = out["request"]["id"]
    r = await c.post(f"{BASE}/publish-requests/{req_id}/approve", json={}, headers=alice)
    assert r.status_code == 409 and "two-person" in r.json()["error"]
    r = await c.post(f"{BASE}/publish-requests/{req_id}/approve", json={"note": "ok"}, headers=bob)
    assert r.status_code == 200
    version = r.json()["version"]
    live = (await c.get(f"{BASE}/environments/production/snapshots/current", headers=alice)).json()
    assert live["version"] == version and live["document"]["assignments"][0]["id"] == "global-pii"


async def test_invalid_publish_is_422_with_errors(env):
    alice, _, _ = await env.keys()
    await seed(env, alice)
    bad = pii_assignment(config={"project_id": 42})
    await env.client.put(f"{BASE}/environments/dev/assignments/global-pii", json=bad, headers=alice)
    r = await env.client.post(f"{BASE}/environments/dev/publish", json={}, headers=alice)
    assert r.status_code == 422 and r.json()["errors"]


async def test_internal_fetch_with_etag(env):
    alice, _, _ = await env.keys()
    await seed(env, alice)
    await env.client.put(f"{BASE}/environments/dev/assignments/global-pii", json=pii_assignment(), headers=alice)
    await env.client.post(f"{BASE}/environments/dev/publish", json={}, headers=alice)
    h = {"X-Internal-Token": TOKEN}
    r1 = await env.client.get(f"{BASE}/internal/environments/dev/snapshot", headers=h)
    assert r1.status_code == 200 and r1.headers["etag"]
    r2 = await env.client.get(
        f"{BASE}/internal/environments/dev/snapshot", headers={**h, "If-None-Match": r1.headers["etag"]}
    )
    assert r2.status_code == 304
    assert (await env.client.get(f"{BASE}/internal/environments/staging/snapshot", headers=h)).status_code == 404
    cat = await env.client.get(f"{BASE}/internal/catalog", headers=h)
    assert cat.status_code == 200 and cat.json()["tenants"] == []


async def test_heartbeat_and_fleet(env):
    alice, _, _ = await env.keys()
    h = {"X-Internal-Token": TOKEN}
    r = await env.client.post(
        f"{BASE}/internal/gateways/heartbeat",
        json={"gateway_id": "gw-1", "environment": "dev", "manifests": [PII_11, NOOP], "snapshot_version": None},
        headers=h,
    )
    assert r.json()["installed"] == ["ai-gateway-pii@1.1.0", "noop@1.0.0"]
    fleet = (await env.client.get(f"{BASE}/environments/dev/gateways", headers=alice)).json()
    assert fleet[0]["gateway_id"] == "gw-1" and fleet[0]["live"] is True


async def test_review_queue_over_http(env):
    alice, _, viewer = await env.keys()
    h = {"X-Internal-Token": TOKEN}
    created = await env.client.post(
        f"{BASE}/internal/reviews",
        json={
            "tenant_id": "acme",
            "environment": "dev",
            "request_id": "r1",
            "stage": "input",
            "agent_id": "bot",
            "guardrail_id": "x",
            "reason": "needs a human",
            "payload": {"text": "secret"},
            "preview": "sec…",
        },
        headers=h,
    )
    rid = created.json()["escalation_id"]
    status = (await env.client.get(f"{BASE}/internal/reviews/{rid}", params={"tenant_id": "acme"}, headers=h)).json()
    assert status["decision"] == "escalate" and status["payload"] is None
    listed = (await env.client.get(f"{BASE}/reviews", params={"status": "pending"}, headers=viewer)).json()
    assert listed[0]["id"] == rid and "payload_enc" not in listed[0]
    assert (await env.client.post(f"{BASE}/reviews/{rid}/approve", json={}, headers=viewer)).status_code == 403
    assert (
        await env.client.post(f"{BASE}/reviews/{rid}/approve", json={"note": "fine"}, headers=alice)
    ).status_code == 200
    status = (await env.client.get(f"{BASE}/internal/reviews/{rid}", params={"tenant_id": "acme"}, headers=h)).json()
    assert status["decision"] == "allow" and status["payload"] == {"text": "secret"}


async def test_simulate_calls_gateway_with_working_set():
    seen = {}

    def gateway(request):
        seen["body"] = request.read()
        seen["token"] = request.headers.get("X-Internal-Token")
        return httpx.Response(200, json={"decision": "modify"})

    env = Env(gateway_handler=gateway)
    alice, _, _ = await env.keys()
    await seed(env, alice)
    await env.client.put(f"{BASE}/environments/dev/assignments/global-pii", json=pii_assignment(), headers=alice)
    await env.client.post(f"{BASE}/tenants", json={"id": "acme", "name": "Acme"}, headers=alice)
    r = await env.client.post(
        f"{BASE}/simulate",
        json={
            "environment": "dev",
            "tenant_id": "acme",
            "stage": "input",
            "request": {"agent_id": "bot", "action": "llm.chat", "payload": {"text": "hi"}},
        },
        headers=alice,
    )
    assert r.status_code == 200, r.text
    assert r.json()["result"] == {"decision": "modify"} and seen["token"] == TOKEN
    assert b"global-pii" in seen["body"]


async def test_simulate_reports_why_the_gateway_refused():
    env = Env(gateway_handler=lambda r: httpx.Response(422, json={"error": "guardrail noop@9.9.9 is not installed"}))
    alice, _, _ = await env.keys()
    await seed(env, alice)
    await env.client.post(f"{BASE}/tenants", json={"id": "acme", "name": "Acme"}, headers=alice)
    body = {
        "environment": "staging",
        "tenant_id": "acme",
        "stage": "input",
        "request": {"agent_id": "bot", "action": "llm.chat", "payload": {"text": "hi"}},
    }
    r = await env.client.post(f"{BASE}/simulate", json=body, headers=alice)
    assert r.status_code == 422 and "noop@9.9.9 is not installed" in r.json()["error"]
    r = await env.client.post(f"{BASE}/simulate", json={**body, "environment": "qa"}, headers=alice)
    assert r.status_code == 422  # unknown environment is rejected before any gateway call


async def test_me_reflects_roles_and_scope():
    env = Env()
    alice, _, viewer = await env.keys()
    svc = AdminKeyService(env.container.ctx)
    _, tenant_admin = await svc.create(None, "acme-admin", ["admin"], tenant_id="acme")
    me = (await env.client.get(f"{BASE}/me", headers=alice)).json()
    assert me["platform"] is True and "publish:approve" in me["permissions"]
    assert me["two_person_environments"] == ["production"] and me["features"]["simulate"] is True
    assert me["features"]["analytics"] is False  # no AUDIT_DSN in tests
    v = (await env.client.get(f"{BASE}/me", headers=viewer)).json()
    assert v["permissions"] == ["read"]
    t = (await env.client.get(f"{BASE}/me", headers={"X-Admin-Key": tenant_admin})).json()
    assert t["tenant_id"] == "acme" and "publish:request" not in t["permissions"]  # platform-only
    assert (await env.client.get(f"{BASE}/me")).status_code == 401


async def test_analytics_without_audit_dsn_is_503():
    env = Env()
    alice, _, _ = await env.keys()
    r = await env.client.get(f"{BASE}/analytics/guardrails", headers=alice)
    assert r.status_code == 503 and "AUDIT_DSN" in r.json()["error"]


async def test_console_is_served_with_security_headers(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><div id=root></div>")
    (tmp_path / "assets" / "index-abc.js").write_text("console.log(1)")
    env = Env()
    settings = Settings(postgres_dsn="postgresql+asyncpg://unused/db", internal_token=TOKEN, console_dir=str(tmp_path))
    app = create_app(settings, env.container)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://cp") as c:
        page = await c.get("/console/")
        asset = await c.get("/console/assets/index-abc.js")
        review = await c.get("/review")
        api = await c.get(f"{BASE}/tenants")
    assert page.status_code == 200 and "root" in page.text
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "connect-src 'self'" in csp
    assert page.headers["cache-control"] == "no-cache" and page.headers["x-frame-options"] == "DENY"
    assert "immutable" in asset.headers["cache-control"]
    assert review.status_code in (302, 307) and review.headers["location"] == "/console/#/reviews"
    assert api.headers["cache-control"] == "no-store" and "content-security-policy" not in api.headers


async def test_console_is_optional():
    env = Env()
    settings = Settings(postgres_dsn="postgresql+asyncpg://unused/db", internal_token=TOKEN, console_dir="/nonexistent")
    app = create_app(settings, env.container)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://cp") as c:
        assert (await c.get("/console/")).status_code == 404
