import json
import re
from pathlib import Path

import httpx
import pytest

from app.plugins.ai_gateway_pii.guardrail import AiGatewayError, AiGatewayPiiGuardrail
from guardrail_sdk import Decision, EnvSecretReader, Manifest, Message, Payload, PluginContext
from guardrail_sdk.conformance import run_conformance
from tests.helpers import MockHttp, make_ctx

MANIFEST = Manifest.from_yaml(Path(__file__).resolve().parents[1] / "app/plugins/ai_gateway_pii/guardrail.yaml")
BASE = "http://ai-gw:8001"
URL = f"{BASE}/ai-gateway/redact/api/text"
PROJECT = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
PATTERNS = {
    "EMAIL_ADDRESS": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "PHONE_NUMBER": re.compile(r"\+?\d[\d ]{8,}\d"),
}


def fake_ai_gateway(request: httpx.Request) -> httpx.Response:
    """Mimics instant-redaction-service with ?include_findings=true (replace mode)."""
    assert request.headers["X-API-Key"] == "engine-key"
    assert request.url.params["include_findings"] == "true"
    body = json.loads(request.content)
    text = body["text"]
    findings = []
    for etype, rx in PATTERNS.items():
        findings += [
            {"entity_type": etype, "start": m.start(), "end": m.end(), "score": 0.95} for m in rx.finditer(text)
        ]
    redacted = text
    for etype, rx in PATTERNS.items():
        redacted = rx.sub(f"[{etype}]", redacted)
    return httpx.Response(
        200,
        json={
            "redacted_text": redacted,
            "redacted": bool(findings),
            "findings": findings,
            "offsets_basis": "normalized_text",
        },
    )


CONFIG = {
    "project_id": PROJECT,
    "base_url": BASE,
    "input": {"on_detect": "modify", "block_entities": ["US_SSN"]},
    "output": {"on_detect": "modify", "block_entities": []},
}


@pytest.fixture
def mock(monkeypatch):
    monkeypatch.setenv("AI_GATEWAY_API_KEY", "engine-key")
    m = MockHttp()
    m.on("POST", URL, fake_ai_gateway)
    return m


async def make_guard(mock, config=CONFIG):
    g = AiGatewayPiiGuardrail(MANIFEST, PluginContext(http=mock.client(), secrets=EnvSecretReader()))
    await g.setup(config)
    return g


async def test_clean_text_allows(mock):
    guard = await make_guard(mock)
    r = await guard.evaluate(make_ctx(), Payload(stage="input", text="What is the capital of France?"))
    assert r.decision == Decision.ALLOW and r.modified_payload is None


async def test_pii_is_redacted(mock):
    guard = await make_guard(mock)
    r = await guard.evaluate(make_ctx(), Payload(stage="input", text="Mail jane.doe@example.com today"))
    assert r.decision == Decision.MODIFY
    assert r.modified_payload.text == "Mail [EMAIL_ADDRESS] today"
    assert [f.type for f in r.findings] == ["EMAIL_ADDRESS"]
    assert "jane.doe" not in r.reason
    sent = mock.calls[0]
    assert json.loads(sent.content)["project_id"] == PROJECT
    assert sent.headers["X-Request-ID"] == "req-1" and sent.headers["traceparent"].startswith("00-" + "a" * 32)


async def test_block_entities(mock):
    guard = await make_guard(mock)
    r = await guard.evaluate(make_ctx(), Payload(stage="input", text="my ssn is 123-45-6789"))
    assert r.decision == Decision.BLOCK and "US_SSN" in r.reason and r.risk_score == 90


async def test_only_configured_roles_are_scanned(mock):
    guard = await make_guard(mock)
    p = Payload(
        stage="input",
        messages=[
            Message(role="system", content="Support email is help@corp.com"),
            Message(role="user", content="I am bob@example.com"),
        ],
    )
    r = await guard.evaluate(make_ctx(), p)
    assert len(mock.calls) == 1
    assert r.modified_payload.messages[0].content == "Support email is help@corp.com"
    assert r.modified_payload.messages[1].content == "I am [EMAIL_ADDRESS]"
    assert r.findings[0].location == "messages[1]"


async def test_blank_text_skips_call(mock):
    guard = await make_guard(mock)
    r = await guard.evaluate(make_ctx(), Payload(stage="output", text="   "))
    assert r.decision == Decision.ALLOW and not mock.calls


@pytest.mark.parametrize("status", [401, 404, 500, 503])
async def test_http_errors_raise_without_body(mock, status):
    guard = await make_guard(mock)
    mock.on("POST", URL, httpx.Response(status, json={"error": "text was jane@x.com"}))
    with pytest.raises(AiGatewayError) as e:
        await guard.evaluate(make_ctx(), Payload(stage="input", text="hi jane@x.com"))
    assert str(status) in str(e.value) and "jane" not in str(e.value)


async def test_old_ai_gateway_without_findings_raises(mock):
    guard = await make_guard(mock)
    mock.on("POST", URL, httpx.Response(200, json={"redacted_text": "x"}))
    with pytest.raises(AiGatewayError, match="include_findings"):
        await guard.evaluate(make_ctx(), Payload(stage="input", text="hi"))


async def test_unsupported_stage_raises(mock):
    guard = await make_guard(mock)
    with pytest.raises(AiGatewayError):
        await guard.evaluate(make_ctx(), Payload(stage="retrieval", chunks=[]))


async def test_config_validation():
    g = AiGatewayPiiGuardrail(MANIFEST, PluginContext(http=httpx.AsyncClient(), secrets=EnvSecretReader()))
    with pytest.raises(ValueError):
        await g.setup({"project_id": "not-a-uuid"})
    with pytest.raises(ValueError):
        await g.setup({"project_id": PROJECT, "typo_option": 1})


async def test_conformance_suite_passes(mock):
    guard = await make_guard(mock)
    mock.on("GET", f"{BASE}/ai-gateway/redact/api/ready", httpx.Response(200, json={"status": "ok"}))
    config = {"project_id": PROJECT, "base_url": BASE}
    report = await run_conformance(guard, config)
    failed = [(c.name, c.detail) for c in report.checks if c.level == "MUST" and not c.passed]
    assert report.passed, failed
