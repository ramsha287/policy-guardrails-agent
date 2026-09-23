"""ai-gateway-pii 1.1.0: retrieval and tool stages."""

from pathlib import Path

import httpx
import pytest

from app.plugins.ai_gateway_pii.guardrail import AiGatewayError, AiGatewayPiiGuardrail
from guardrail_sdk import Chunk, Decision, EnvSecretReader, Manifest, Payload, PluginContext, ToolCall
from guardrail_sdk.conformance import run_conformance
from tests import fake_ai_gateway as fake
from tests.helpers import MockHttp, make_ctx

PLUGIN_DIR = Path(__file__).resolve().parents[1] / "app/plugins/ai_gateway_pii"
MANIFEST = Manifest.from_yaml(PLUGIN_DIR / "guardrail-1.1.0.yaml")
PROJECT = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
CONFIG = {
    "project_id": PROJECT,
    "base_url": fake.BASE,
    "retrieval": {"on_detect": "modify", "block_entities": ["US_SSN"], "drop_chunk_if_entities_gt": 2},
    "tool": {
        "external_tools": ["http.*", "email.send"],
        "external_on_detect": "block",
        "result": {"on_detect": "modify", "block_entities": []},
    },
}


@pytest.fixture
def mock(monkeypatch):
    monkeypatch.setenv("AI_GATEWAY_API_KEY", "engine-key")
    m = MockHttp()
    for p in ("/text", "/text/batch", "/json"):
        m.on("POST", fake.PREFIX + p, fake.handle)
    m.on("GET", fake.PREFIX + "/ready", httpx.Response(200, json={"status": "ok"}))
    return m


async def make_guard(mock, config=CONFIG):
    g = AiGatewayPiiGuardrail(MANIFEST, PluginContext(http=mock.client(), secrets=EnvSecretReader()))
    await g.setup(config)
    return g


def test_manifest_versions_side_by_side():
    old = Manifest.from_yaml(PLUGIN_DIR / "guardrail.yaml")
    assert old.version == "1.0.0" and [s.value for s in old.stages] == ["input", "output"]
    assert [s.value for s in MANIFEST.stages] == ["input", "retrieval", "tool", "output"]


# ---- retrieval --------------------------------------------------------------------------


def chunks(*texts):
    return Payload(stage="retrieval", chunks=[Chunk(id=f"c{i}", text=t, source="kb") for i, t in enumerate(texts)])


async def test_retrieval_clean_allows(mock):
    g = await make_guard(mock)
    r = await g.evaluate(make_ctx(), chunks("Revenue grew 12%.", "Churn fell."))
    assert r.decision == Decision.ALLOW
    assert len(mock.calls) == 1  # one batch call for all chunks


async def test_retrieval_redacts_and_drops(mock):
    g = await make_guard(mock)
    p = chunks(
        "Revenue grew 12%.",
        "Contact jane@example.com",
        "SSN 123-45-6789 on file",
        "a@x.com b@y.com c@z.com",
    )
    r = await g.evaluate(make_ctx(), p)
    assert r.decision == Decision.MODIFY
    out = {c.id: c.text for c in r.modified_payload.chunks}
    assert out == {"c0": "Revenue grew 12%.", "c1": "Contact [EMAIL_ADDRESS]"}
    assert r.metadata["dropped_chunks"] == ["c2", "c3"]  # blocked entity; more than 2 entities
    assert r.modified_payload.chunks[1].source == "kb"
    assert p.same_shape_as(r.modified_payload)
    assert all(f.location.startswith("chunks[c") for f in r.findings)


async def test_retrieval_batches_over_100_chunks(mock):
    g = await make_guard(mock)
    r = await g.evaluate(make_ctx(), chunks(*[f"doc {i}" for i in range(250)]))
    assert r.decision == Decision.ALLOW and len(mock.calls) == 3


async def test_retrieval_duplicate_chunk_ids_are_safe(mock):
    g = await make_guard(mock)
    p = Payload(stage="retrieval", chunks=[Chunk(id="dup", text="x@y.com"), Chunk(id="dup", text="clean")])
    r = await g.evaluate(make_ctx(), p)
    assert [c.text for c in r.modified_payload.chunks] == ["[EMAIL_ADDRESS]", "clean"]


async def test_retrieval_block_mode(mock):
    g = await make_guard(mock, {**CONFIG, "retrieval": {"on_detect": "block"}})
    r = await g.evaluate(make_ctx(), chunks("mail me at q@w.com"))
    assert r.decision == Decision.BLOCK


async def test_retrieval_old_service_without_batch_fails(mock):
    mock.on("POST", fake.PREFIX + "/text/batch", httpx.Response(404, json={"error": "nope"}))
    g = await make_guard(mock)
    with pytest.raises(AiGatewayError, match="404"):
        await g.evaluate(make_ctx(), chunks("hello"))


# ---- tool -------------------------------------------------------------------------------


def tool(name, arguments=None, result=None):
    return Payload(stage="tool", tool_call=ToolCall(name=name, arguments=arguments or {}, result=result))


async def test_tool_result_is_redacted(mock):
    g = await make_guard(mock)
    p = tool("database.read", {"query": "select email from customers"}, {"rows": [{"email": "bob@x.com", "n": 3}]})
    r = await g.evaluate(make_ctx(), p)
    assert r.decision == Decision.MODIFY
    assert r.modified_payload.tool_call.result == {"rows": [{"email": "[EMAIL_ADDRESS]", "n": 3}]}
    assert r.modified_payload.tool_call.arguments == {"query": "select email from customers"}
    assert [f.location for f in r.findings] == ["tool_call.result.rows[0].email"]


async def test_pii_to_external_tool_is_blocked(mock):
    g = await make_guard(mock)
    r = await g.evaluate(make_ctx(), tool("http.post", {"url": "https://api.example.com", "body": "to jane@x.com"}))
    assert r.decision == Decision.BLOCK and "external tool http.post" in r.reason and r.risk_score >= 85


async def test_pii_to_internal_tool_is_redacted(mock):
    g = await make_guard(mock)
    r = await g.evaluate(make_ctx(), tool("crm.lookup", {"email": "jane@x.com"}))
    assert r.decision == Decision.MODIFY
    assert r.modified_payload.tool_call.arguments == {"email": "[EMAIL_ADDRESS]"}


async def test_string_result_and_before_call(mock):
    g = await make_guard(mock)
    assert (await g.evaluate(make_ctx(), tool("search", {"q": "weather"}))).decision == Decision.ALLOW
    r = await g.evaluate(make_ctx(), tool("search", {"q": "weather"}, "Call +1 212 555 0199"))
    assert r.modified_payload.tool_call.result == "Call [PHONE_NUMBER]"


async def test_tool_block_entities(mock):
    cfg = {**CONFIG, "tool": {"result": {"block_entities": ["US_SSN"]}}}
    g = await make_guard(mock, cfg)
    r = await g.evaluate(make_ctx(), tool("db.read", {}, {"ssn": "123-45-6789"}))
    assert r.decision == Decision.BLOCK and "US_SSN" in r.reason


async def test_conformance_all_four_stages(mock):
    g = await make_guard(mock)
    report = await run_conformance(g, CONFIG)
    failed = [(c.name, c.detail) for c in report.checks if c.level == "MUST" and not c.passed]
    assert report.passed, failed
    stages = {c.name.split("[")[0] for c in report.checks if "[" in c.name}
    assert stages == {"input", "retrieval", "tool", "output"}
