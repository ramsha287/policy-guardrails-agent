"""Phase 4 exit criteria against the live stack: change guardrails without redeploying.

export GUARDRAIL_E2E_URL=http://localhost:8100 CONTROL_PLANE_E2E_URL=http://localhost:8200
export GUARDRAIL_E2E_KEY=...   # DEMO_GATEWAY_API_KEY from /bootstrap/dev.env
export CP_E2E_ADMIN_KEY=...    # CP_ADMIN_KEY from /bootstrap/cp.env
pytest tests/e2e/test_control_plane.py -v
"""

import asyncio
import os

import httpx
import pytest

GW = os.environ.get("GUARDRAIL_E2E_URL")
CP = os.environ.get("CONTROL_PLANE_E2E_URL")
KEY = os.environ.get("GUARDRAIL_E2E_KEY")
ADMIN = os.environ.get("CP_E2E_ADMIN_KEY")
pytestmark = pytest.mark.skipif(not (GW and CP and KEY and ADMIN), reason="live control-plane e2e not configured")

BODY = {
    "agent_id": "research-agent",
    "action": "llm.chat",
    "data_classification": "INTERNAL",
    "payload": {"text": "mail jane.doe@example.com"},
}


async def wait_for_snapshot(gw: httpx.AsyncClient, version: str, wait_seconds: float = 45.0) -> None:
    deadline = asyncio.get_running_loop().time() + wait_seconds
    while asyncio.get_running_loop().time() < deadline:
        if (await gw.get("/version")).json().get("snapshot_version") == version:
            return
        await asyncio.sleep(1)
    raise AssertionError(f"gateway did not load {version} within {wait_seconds}s")


async def test_disable_publish_and_rollback_without_redeploy():
    admin = {"X-Admin-Key": ADMIN}
    async with (
        httpx.AsyncClient(base_url=CP, headers=admin, timeout=30) as cp,
        httpx.AsyncClient(base_url=GW, headers={"X-API-Key": KEY}, timeout=30) as gw,
    ):
        fleet = (await cp.get("/cp/v1/environments/dev/gateways")).json()
        assert any(g["live"] for g in fleet), fleet
        before = (await cp.get("/cp/v1/environments/dev/snapshots/current")).json()["version"]
        pii = next(
            a
            for a in (await cp.get("/cp/v1/environments/dev/assignments")).json()
            if a["assignment"]["guardrail_id"] == "ai-gateway-pii"
        )["assignment"]["id"]

        redacted = (await gw.post("/v1/guard/input", json=BODY)).json()
        assert "[EMAIL_ADDRESS]" in redacted["payload"]["text"]

        r = await cp.patch(f"/cp/v1/environments/dev/assignments/{pii}", json={"enabled": False})
        assert r.status_code == 200, r.text
        published = (await cp.post("/cp/v1/environments/dev/publish", json={"note": "e2e: disable pii"})).json()
        assert published["status"] == "published", published
        await wait_for_snapshot(gw, published["snapshot"]["version"])
        assert (await gw.post("/v1/guard/input", json=BODY)).json()["payload"]["text"] == BODY["payload"]["text"]

        rb = (await cp.post("/cp/v1/environments/dev/rollback", json={"version": before})).json()
        assert rb["status"] == "published", rb
        await wait_for_snapshot(gw, rb["snapshot"]["version"])
        assert "[EMAIL_ADDRESS]" in (await gw.post("/v1/guard/input", json=BODY)).json()["payload"]["text"]


async def test_key_revocation_reaches_gateway():
    admin = {"X-Admin-Key": ADMIN}
    async with (
        httpx.AsyncClient(base_url=CP, headers=admin, timeout=30) as cp,
        httpx.AsyncClient(base_url=GW, timeout=30) as gw,
    ):
        created = (await cp.post("/cp/v1/tenants/demo/api-keys", json={"name": "e2e-temp"})).json()
        headers = {"X-API-Key": created["key"]}
        for _ in range(30):  # catalog publish -> event/poll -> gateway
            if (await gw.post("/v1/guard/input", json=BODY, headers=headers)).status_code == 200:
                break
            await asyncio.sleep(1)
        else:
            raise AssertionError("new key never became valid")
        await cp.delete(f"/cp/v1/tenants/demo/api-keys/{created['id']}")
        for _ in range(30):
            if (await gw.post("/v1/guard/input", json=BODY, headers=headers)).status_code == 401:
                return
            await asyncio.sleep(1)
        raise AssertionError("revoked key still accepted after 30s")
