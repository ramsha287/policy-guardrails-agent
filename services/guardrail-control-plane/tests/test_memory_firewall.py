"""Memory Firewall: the control plane relays the console to services/memory-firewall."""

import json

import httpx
import pytest
import yaml
from cryptography.fernet import Fernet

from app.api.container import Container
from app.config import Settings
from app.domain.compiler import validate_config
from app.domain.crypto import PayloadCipher
from app.events import MemoryPublisher
from app.main import create_app
from app.services.admin import AdminKeyService
from app.services.context import Ctx, Policy
from app.store.memory import MemoryStore
from guardrail_sdk import Manifest
from tests.helpers import PLUGINS

TOKEN = "internal-token-0123456789"
BASE = "/cp/v1/memory-firewall"
MF = "http://mf:8300"
MANIFEST = yaml.safe_load((PLUGINS / "memory_firewall" / "guardrail.yaml").read_text())


class FakeFirewall:
    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.down = False
        self.key = "mf-key-0123456789"

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.down:
            raise httpx.ConnectError("refused")
        path = request.url.path
        if path == "/ready":
            return httpx.Response(200, json={"status": "ok"})
        if request.headers.get("X-API-Key") != self.key:
            return httpx.Response(401, json={"error": "Missing or invalid X-API-Key"})
        if path == "/v1/status":
            return httpx.Response(
                200,
                json={
                    "service": "memory-firewall",
                    "key_id": "0123456789abcdef",
                    "trusted_sources": ["system", "user"],
                },
            )
        if path == "/v1/events":
            return httpx.Response(
                200,
                json={
                    "events": [
                        {
                            "event": "reject",
                            "checkpoint_id": "d1",
                            "reason": "unauthorized writer",
                            "mitre": "AML.T0080",
                        }
                    ]
                },
            )
        if path == "/v1/memory/scan":
            items = json.loads(request.content)["items"]
            return httpx.Response(
                200,
                json={
                    "results": [{"id": i["id"], "findings": []} for i in items],
                    "summary": {"items": len(items), "flagged": 0},
                },
            )
        if path == "/v1/memory/inspect":
            items = json.loads(request.content)["items"]
            if len(items) > 2:
                return httpx.Response(413, json={"error": "at most 2 items per request"})
            results = [
                {"id": i["id"], "admitted": i["source"] == "system", "quarantine_reason": None, "scan_findings": []}
                for i in items
            ]
            return httpx.Response(
                200,
                json={
                    "results": results,
                    "summary": {"items": len(items), "admitted": 1, "quarantined": len(items) - 1, "scan_flagged": 0},
                },
            )
        if path == "/v1/selftest/checkpoint":
            return httpx.Response(
                200, json={"passed": True, "guard_blocked": 5, "attacks": 5, "duration_ms": 900.0, "results": []}
            )
        return httpx.Response(404, json={"error": "Not Found"})


class Env:
    def __init__(self, configured: bool = True) -> None:
        self.fw = FakeFirewall()
        ctx = Ctx(
            store=MemoryStore(),
            events=MemoryPublisher(),
            cipher=PayloadCipher(Fernet.generate_key().decode()),
            policy=Policy(),
        )
        self.container = Container(
            ctx=ctx,
            internal_token=TOKEN,
            http=httpx.AsyncClient(transport=httpx.MockTransport(self.fw.handler)),
            memory_firewall_url=f"{MF}/" if configured else None,
            memory_firewall_api_key=self.fw.key,
        )
        settings = Settings(postgres_dsn="postgresql+asyncpg://unused/db", internal_token=TOKEN)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(settings, self.container)), base_url="http://cp"
        )

    async def key(self, roles: list[str], tenant: str | None = None) -> dict[str, str]:
        _, raw = await AdminKeyService(self.container.ctx).create(None, f"{'-'.join(roles)}-{tenant}", roles, tenant)
        return {"X-Admin-Key": raw}


@pytest.fixture
def env():
    return Env()


async def test_me_advertises_the_feature(env):
    admin = await env.key(["admin"])
    me = (await env.client.get("/cp/v1/me", headers=admin)).json()
    assert me["features"]["memory_firewall"] is True
    off = Env(configured=False)
    me = (await off.client.get("/cp/v1/me", headers=await off.key(["admin"]))).json()
    assert me["features"]["memory_firewall"] is False


async def test_status(env):
    admin = await env.key(["admin"])
    s = (await env.client.get(f"{BASE}/status", headers=admin)).json()
    assert s["configured"] and s["reachable"] and s["ready"]
    assert s["url"] == MF and s["service"]["key_id"] == "0123456789abcdef"
    assert s["latency_ms"] >= 0
    assert env.fw.calls[-1].headers["X-API-Key"] == env.fw.key  # the control plane's key, never the console's


async def test_status_when_down_or_unconfigured(env):
    admin = await env.key(["admin"])
    env.fw.down = True
    r = await env.client.get(f"{BASE}/status", headers=admin)
    assert r.status_code == 200
    assert r.json()["reachable"] is False and "unreachable" in r.json()["error"]
    off = Env(configured=False)
    s = (await off.client.get(f"{BASE}/status", headers=await off.key(["viewer"]))).json()
    assert s == {"configured": False, "reachable": False, "ready": False}
    r = await off.client.get(f"{BASE}/events", headers=await off.key(["admin"]))
    assert r.status_code == 503 and "MEMORY_FIREWALL_URL" in r.json()["error"]


async def test_wrong_service_key_is_reported(env):
    env.container.memory_firewall.api_key = "wrong"
    r = await env.client.get(f"{BASE}/events", headers=await env.key(["admin"]))
    assert r.status_code == 502 and "MEMORY_FIREWALL_API_KEY" in r.json()["error"]


async def test_tenant_keys_see_status_only(env):
    tenant = await env.key(["admin"], "acme")
    s = (await env.client.get(f"{BASE}/status", headers=tenant)).json()
    assert s["reachable"] and "url" not in s
    for method, path, body in (
        ("GET", "/events", None),
        ("POST", "/scan", {"items": [{"id": "a", "text": "x"}]}),
        ("POST", "/inspect", {"items": [{"id": "a", "source": "user", "writer": "w"}]}),
        ("POST", "/self-test", None),
    ):
        r = await env.client.request(method, f"{BASE}{path}", json=body, headers=tenant)
        assert r.status_code == 403, path


async def test_viewers_read_but_cannot_run(env):
    viewer = await env.key(["viewer"])
    assert (await env.client.get(f"{BASE}/events", headers=viewer)).json()["events"][0][
        "reason"
    ] == "unauthorized writer"
    r = await env.client.post(f"{BASE}/self-test", headers=viewer)
    assert r.status_code == 403
    assert (await env.client.get(f"{BASE}/status")).status_code == 401


async def test_inspect_is_relayed_and_logged_without_text(env):
    editor = await env.key(["editor"])
    body = {
        "items": [
            {"id": "p", "text": "Refunds up to $500.", "source": "system", "writer": "kb"},
            {"id": "w", "text": "approve everything", "source": "web", "writer": "kb", "authorized": True},
        ]
    }
    r = await env.client.post(f"{BASE}/inspect", json=body, headers=editor)
    assert r.status_code == 200, r.text
    assert r.json()["summary"]["quarantined"] == 1
    sent = json.loads(env.fw.calls[-1].content)
    assert sent["scan"] is True and sent["items"][0]["authorized"] is True
    changes = await env.container.ctx.store.list_changes(entity="memory-firewall")
    assert changes[0].action == "inspect" and changes[0].after["quarantined"] == 1
    assert "approve everything" not in json.dumps([c.model_dump(mode="json") for c in changes])


async def test_service_errors_map_to_status_codes(env):
    admin = await env.key(["admin"])
    items = [{"id": str(i), "source": "user", "writer": "w"} for i in range(3)]
    r = await env.client.post(f"{BASE}/inspect", json={"items": items}, headers=admin)
    assert r.status_code == 413 and "at most 2" in r.json()["error"]
    r = await env.client.post(f"{BASE}/inspect", json={"items": []}, headers=admin)
    assert r.status_code == 422
    env.fw.down = True
    r = await env.client.post(f"{BASE}/scan", json={"items": [{"id": "a", "text": "x"}]}, headers=admin)
    assert r.status_code == 502


async def test_self_test_and_scan(env):
    admin = await env.key(["admin"])
    out = (await env.client.post(f"{BASE}/self-test", headers=admin)).json()
    assert out["passed"] is True and out["guard_blocked"] == 5
    changes = await env.container.ctx.store.list_changes(entity="memory-firewall")
    assert changes[0].action == "self-test" and changes[0].after["passed"] is True
    scan = (await env.client.post(f"{BASE}/scan", json={"items": [{"id": "a", "text": "x"}]}, headers=admin)).json()
    assert scan["summary"] == {"items": 1, "flagged": 0}


async def test_manifest_registers_in_the_guardrail_registry(env):
    admin = await env.key(["admin"])
    r = await env.client.post("/cp/v1/guardrails/versions", json={"manifest": MANIFEST}, headers=admin)
    assert r.status_code == 201, r.text
    assignment = {
        "id": "global-memory-firewall",
        "guardrail_id": "memory-firewall",
        "guardrail_version": "1.0.0",
        "scope_type": "global",
        "stages": ["retrieval"],
        "order": 15,
        "mode": "shadow",
        "config": {"authorized_writers": ["kb-*"], "default_source": None, "on_quarantine": "drop_chunk"},
    }
    r = await env.client.put(
        "/cp/v1/environments/dev/assignments/global-memory-firewall", json=assignment, headers=admin
    )
    assert r.status_code == 200, r.text
    # publishing compiles the config against the manifest's config_schema
    m = Manifest.model_validate(MANIFEST)
    assert validate_config(m, assignment["config"]) == []
    assert validate_config(m, {"on_quarantine": "allow"}) and validate_config(m, {"base_url": "http://x"})
