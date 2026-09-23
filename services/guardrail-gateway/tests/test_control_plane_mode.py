"""CONFIG_SOURCE=control_plane: catalog-based auth/scoring, ETag sync, disk cache, escalation."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.config import APP_DIR
from app.engine.escalation import hold_for_review, preview_of
from app.engine.pipeline import GuardrailEngine
from app.engine.registry import PluginRegistry, SnapshotHolder
from app.engine.remote import CatalogHolder, ControlPlaneClient, ControlPlaneSync, DocCache
from app.gateway.auth import Authenticator
from guardrail_sdk import Decision, EnvSecretReader, Payload, PluginContext, Stage
from tests.helpers import bind, make_ctx, result, snapshot


def h(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


CATALOG = {
    "version": "catalog-1",
    "tenants": [
        {
            "id": "acme",
            "name": "Acme",
            "status": "active",
            "api_keys": [
                {"id": "k1", "name": "bot", "key_hash": h("gk_good"), "scopes": ["guard:invoke"]},
                {"id": "k2", "name": "prod-only", "key_hash": h("gk_prod"), "environments": ["production"]},
                {
                    "id": "k3",
                    "name": "expired",
                    "key_hash": h("gk_old"),
                    "expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
                },
            ],
            "agents": [{"agent_id": "bot", "base_trust_score": 70, "allowed_tools": ["crm.lookup"]}],
            "actions": [{"action": "llm.chat", "resource_pattern": "*", "base_risk_score": 15}],
            "modifiers": [{"kind": "classification", "value": "PII", "delta": 20}],
        },
        {
            "id": "suspended-co",
            "name": "S",
            "status": "suspended",
            "api_keys": [{"id": "k9", "name": "x", "key_hash": h("gk_susp")}],
        },
    ],
}
SNAPSHOT = {
    "version": "dev-00001-aaaaaaaa",
    "environment": "dev",
    "assignments": [
        {"id": "noop", "guardrail_id": "noop", "guardrail_version": "1.0.0", "stages": ["input"], "mode": "enforce"}
    ],
}


async def test_catalog_holder_auth_rules():
    holder = CatalogHolder("dev")
    assert holder.apply(CATALOG)
    auth = Authenticator(holder, ttl_seconds=0, negative_ttl_seconds=0)
    good = await auth.authenticate("gk_good")
    assert good is not None and good.tenant_id == "acme"
    assert await auth.authenticate("gk_prod") is None  # restricted to production
    assert await auth.authenticate("gk_old") is None  # expired
    assert await auth.authenticate("gk_susp") is None  # tenant suspended
    cat = await holder.load("acme")
    assert cat.agent("bot").base_trust_score == 70 and cat.modifier("classification", "PII") == 20
    assert (await holder.load("unknown")).agents == {}
    prod = CatalogHolder("production")
    prod.apply(CATALOG)
    assert await Authenticator(prod, ttl_seconds=0).authenticate("gk_prod") is not None
    assert not holder.apply({"version": 1, "tenants": "nope"}) and holder.version == "catalog-1"


class FakeCP:
    def __init__(self):
        self.snapshot = dict(SNAPSHOT)
        self.catalog = dict(CATALOG)
        self.down = False
        self.calls: list[tuple[str, str | None]] = []
        self.heartbeats: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("down")
        assert request.headers["X-Internal-Token"] == "tok-0123456789abcdef"
        path = request.url.path
        inm = request.headers.get("If-None-Match")
        self.calls.append((path, inm))
        if path.endswith("/gateways/heartbeat"):
            self.heartbeats.append(json.loads(request.content))
            return httpx.Response(200, json={})
        doc = self.snapshot if path.endswith("/environments/dev/snapshot") else self.catalog
        if doc is None:
            return httpx.Response(404, json={"error": "none"})
        etag = f'"{doc["version"]}"'
        if inm == etag:
            return httpx.Response(304)
        return httpx.Response(200, json=doc, headers={"ETag": etag})


def make_sync(cp: FakeCP, tmp_path):
    http = httpx.AsyncClient(transport=httpx.MockTransport(cp))
    registry = PluginRegistry([APP_DIR / "plugins"], PluginContext(http=http, secrets=EnvSecretReader()))
    registry.discover()
    snaps = SnapshotHolder(registry, None, "dev")
    cat = CatalogHolder("dev")
    sync = ControlPlaneSync(
        ControlPlaneClient(http, "http://cp:8200", "tok-0123456789abcdef"),
        snaps,
        cat,
        registry,
        DocCache(tmp_path, "dev"),
        environment="dev",
        gateway_id="gw-test",
    )
    return sync, snaps, cat


async def test_sync_fetches_caches_and_uses_etags(tmp_path):
    cp = FakeCP()
    sync, snaps, cat = make_sync(cp, tmp_path)
    await sync.start()
    assert snaps.version == SNAPSHOT["version"] and cat.version == "catalog-1"
    assert (tmp_path / "snapshot-dev.json").exists() and (tmp_path / "catalog.json").exists()
    await sync.refresh("snapshot")
    assert cp.calls[-1][1] == f'"{SNAPSHOT["version"]}"'  # conditional request -> 304
    cp.snapshot = {**SNAPSHOT, "version": "dev-00002-bbbbbbbb", "assignments": []}
    await sync.refresh("snapshot")
    assert snaps.version == "dev-00002-bbbbbbbb"


async def test_bad_snapshot_keeps_last_good_and_is_reported(tmp_path):
    cp = FakeCP()
    sync, snaps, _ = make_sync(cp, tmp_path)
    await sync.start()
    cp.snapshot = {
        **SNAPSHOT,
        "version": "dev-00003-cccccccc",
        "assignments": [{"id": "x", "guardrail_id": "noop", "guardrail_version": "9.9.9", "stages": ["input"]}],
    }
    await sync.refresh("snapshot")
    assert snaps.version == SNAPSHOT["version"] and "9.9.9" in snaps.last_error
    body = sync.heartbeat_body()
    assert body["gateway_id"] == "gw-test" and "9.9.9" in body["last_error"]
    assert {"ai-gateway-pii", "noop"} <= {m["id"] for m in body["manifests"]}
    # cache still holds the good version
    assert json.loads((tmp_path / "snapshot-dev.json").read_text())["document"]["version"] == SNAPSHOT["version"]


async def test_starts_from_disk_cache_when_control_plane_is_down(tmp_path):
    cp = FakeCP()
    first, _, _ = make_sync(cp, tmp_path)
    await first.start()
    cp.down = True
    sync, snaps, cat = make_sync(cp, tmp_path)
    await sync.start()
    assert snaps.version == SNAPSHOT["version"] and cat.version == "catalog-1"
    assert sync.control_plane_reachable is False and "unreachable" in sync.last_sync_error


async def test_no_control_plane_and_no_cache_stays_not_ready(tmp_path):
    cp = FakeCP()
    cp.down = True
    sync, snaps, cat = make_sync(cp, tmp_path)
    await sync.start()
    assert snaps.current is None and cat.version is None


async def test_escalate_holds_payload_when_review_queue_exists():
    p = Payload(stage="input", text="hello")
    snap = snapshot(bind("human-check", result("escalate", "looks odd", 70)))
    held = await GuardrailEngine(escalate_as_block=False).run(snap, Stage.INPUT, make_ctx(), p, None)
    assert held.decision == Decision.ESCALATE and held.payload == p
    blocked = await GuardrailEngine(escalate_as_block=True).run(snap, Stage.INPUT, make_ctx(), p, None)
    assert blocked.decision == Decision.BLOCK and blocked.payload is None


@pytest.mark.parametrize(
    "payload,expected",
    [
        (Payload(stage="input", text="x" * 900), "x" * 500),
        (Payload(stage="input", messages=[{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]), "b"),
        (Payload(stage="retrieval", chunks=[{"id": "1", "text": "c1"}, {"id": "2", "text": "c2"}]), "c1 | c2"),
    ],
)
def test_preview(payload, expected):
    assert preview_of(payload) == expected


async def _escalated():
    p = Payload(stage="input", text="transfer all funds")
    snap = snapshot(bind("human-check", result("escalate", "high-value action", 75)))
    return p, await GuardrailEngine(escalate_as_block=False).run(snap, Stage.INPUT, make_ctx(), p, None)


async def test_hold_for_review_files_review_with_held_payload():
    seen = {}

    def cp(request):
        seen.update(json.loads(request.content))
        return httpx.Response(201, json={"escalation_id": "rev-123", "expires_at": "x"})

    client = ControlPlaneClient(httpx.AsyncClient(transport=httpx.MockTransport(cp)), "http://cp", "t")
    p, outcome = await _escalated()
    held, esc = await hold_for_review(client, make_ctx(), Stage.INPUT, outcome)
    assert esc == "rev-123" and held.decision == Decision.ESCALATE
    assert seen["guardrail_id"] == "human-check" and seen["payload"]["text"] == "transfer all funds"
    assert seen["preview"] == "transfer all funds" and seen["tenant_id"] == "demo"


async def test_hold_for_review_fails_closed():
    def down(request):
        raise httpx.ConnectError("down")

    client = ControlPlaneClient(httpx.AsyncClient(transport=httpx.MockTransport(down)), "http://cp", "t")
    _, outcome = await _escalated()
    blocked, esc = await hold_for_review(client, make_ctx(), Stage.INPUT, outcome)
    assert esc is None and blocked.decision == Decision.BLOCK and "unavailable" in blocked.reason
    no_queue, esc2 = await hold_for_review(None, make_ctx(), Stage.INPUT, outcome)
    assert esc2 is None and no_queue.decision == Decision.BLOCK
