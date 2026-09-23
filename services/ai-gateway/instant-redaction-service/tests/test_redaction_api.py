import asyncio

import httpx

from tests.conftest import P1, P2

BASE = "/ai-gateway/redact/api"


async def test_text_is_backward_compatible(client):
    r = await client.post(f"{BASE}/text", json={"text": "Mail jane.doe@example.com", "project_id": P1})
    assert r.status_code == 200
    assert set(r.json()) == {"redacted_text"}
    assert "[EMAIL_ADDRESS]" in r.json()["redacted_text"]


async def test_text_findings(client):
    text = "Call John Smith at john@example.com, id EMP-123456"
    r = await client.post(f"{BASE}/text", params={"include_findings": "true"}, json={"text": text, "project_id": P1})
    body = r.json()
    assert r.status_code == 200 and body["redacted"] is True and body["offsets_basis"] == "normalized_text"
    types = {f["entity_type"] for f in body["findings"]}
    assert {"PERSON", "EMAIL_ADDRESS", "EMPLOYEE_ID"} <= types
    assert "john@example.com" not in r.text and "EMP-123456" not in r.text
    for f in body["findings"]:
        assert 0 <= f["start"] < f["end"] and 0.0 <= f["score"] <= 1.0


async def test_clean_text_has_no_findings(client):
    r = await client.post(
        f"{BASE}/text", params={"include_findings": "true"},
        json={"text": "What is the capital of France?", "project_id": P1},
    )
    assert r.json()["redacted"] is False and r.json()["findings"] == []


async def test_batch_preserves_order_and_ids(client):
    items = [
        {"id": "c1", "text": "Quarterly revenue grew 12%."},
        {"id": "c2", "text": "Contact jane.doe@example.com for access."},
        {"id": "c3", "text": "Employee EMP-654321 approved it."},
    ]
    r = await client.post(f"{BASE}/text/batch", json={"project_id": P1, "items": items})
    assert r.status_code == 200, r.text
    results = r.json()["results"]
    assert [x["id"] for x in results] == ["c1", "c2", "c3"]
    assert [x["redacted"] for x in results] == [False, True, True]
    assert "jane.doe" not in r.text


async def test_batch_limits(client):
    too_many = [{"id": str(i), "text": "x"} for i in range(101)]
    assert (await client.post(f"{BASE}/text/batch", json={"project_id": P1, "items": too_many})).status_code == 400
    dupes = [{"id": "a", "text": "x"}, {"id": "a", "text": "y"}]
    assert (await client.post(f"{BASE}/text/batch", json={"project_id": P1, "items": dupes})).status_code == 400


async def test_json_redaction_with_paths(client):
    data = {"query": "select *  from customers", "rows": [{"email": "bob@example.com", "age": 41}], "note": ""}
    r = await client.post(f"{BASE}/json", params={"include_findings": "true"}, json={"project_id": P1, "data": data})
    body = r.json()
    assert r.status_code == 200 and body["redacted"] is True
    assert body["data"]["rows"][0]["email"] == "[EMAIL_ADDRESS]"
    assert body["data"]["rows"][0]["age"] == 41
    assert body["data"]["query"] == "select *  from customers"  # untouched strings keep their exact text
    assert body["data"]["note"] == ""
    assert [f["path"] for f in body["findings"]] == ["$.rows[0].email"]
    assert "bob@example.com" not in r.text


async def test_json_without_findings_flag(client):
    r = await client.post(f"{BASE}/json", json={"project_id": P1, "data": ["a@b.com"]})
    assert set(r.json()) == {"data", "redacted"}


async def test_unknown_project_is_404(client):
    r = await client.post(
        f"{BASE}/text/batch", json={"project_id": "33333333-3333-3333-3333-333333333333", "items": [{"id": "a", "text": "x"}]}
    )
    assert r.status_code == 404


async def test_custom_patterns_do_not_leak_between_concurrent_requests(client):
    """Custom recognizers are per request (ad_hoc), so project 2 never sees project 1's EMP pattern."""
    text = "EMP-123456 and ORD-9876"

    async def call(project):
        r = await client.post(f"{BASE}/text", params={"include_findings": "true"}, json={"text": text, "project_id": project})
        return {f["entity_type"] for f in r.json()["findings"]}

    results = await asyncio.gather(*[call(P1 if i % 2 == 0 else P2) for i in range(20)])
    for i, types in enumerate(results):
        assert types == ({"EMPLOYEE_ID"} if i % 2 == 0 else {"ORDER_ID"})


async def test_ready_and_version(client):
    assert (await client.get(f"{BASE}/ready")).status_code == 200
    v = (await client.get(f"{BASE}/version")).json()
    assert "text.batch" in v["features"] and "json" in v["features"]


async def test_project_client_cache_and_invalidation():
    from clients.project_client import ProjectClient

    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"id": "p1", "entities": []})

    pc = ProjectClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)), "http://ps", cache_ttl_seconds=60)
    await pc.get_project("p1")
    await pc.get_project("p1")
    assert len(calls) == 1
    pc.invalidate("p1")
    await pc.get_project("p1")
    assert len(calls) == 2
    no_cache = ProjectClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)), "http://ps", cache_ttl_seconds=0)
    await no_cache.get_project("p1")
    await no_cache.get_project("p1")
    assert len(calls) == 4
