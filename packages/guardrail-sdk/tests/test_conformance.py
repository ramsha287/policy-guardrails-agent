import re

import httpx
import pytest
from pydantic import BaseModel, ConfigDict

from guardrail_sdk import (
    Decision,
    EnvSecretReader,
    Finding,
    Guardrail,
    GuardrailResult,
    Manifest,
    Payload,
    PluginContext,
    SecurityContext,
)
from guardrail_sdk.conformance import run_conformance

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


class Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    replacement: str = "[EMAIL]"


class EmailRedactor(Guardrail):
    config_model = Cfg

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        text = payload.text or " ".join(m.content for m in payload.messages or [])
        hits = list(EMAIL.finditer(text))
        if not hits:
            return GuardrailResult(decision=Decision.ALLOW, reason="clean")
        data = payload.model_dump()
        if data["text"] is not None:
            data["text"] = EMAIL.sub(self.config.replacement, data["text"])
        for m in data["messages"] or []:
            m["content"] = EMAIL.sub(self.config.replacement, m["content"])
        return GuardrailResult(
            decision=Decision.MODIFY,
            reason=f"{len(hits)} email(s)",
            findings=[Finding(type="EMAIL", start=h.start(), end=h.end()) for h in hits],
            modified_payload=Payload.model_validate(data),
        )


class Leaky(EmailRedactor):
    async def evaluate(self, context, payload):
        r = await super().evaluate(context, payload)
        if r.findings:
            r.reason = f"found {EMAIL.search(payload.text or payload.messages[-1].content).group(0)}"
        return r


MANIFEST = Manifest.model_validate(
    dict(
        id="email-redactor",
        version="1.0.0",
        kind="local",
        stages=["input", "output"],
        description="d",
        owner="o",
        data_handling="none",
        decisions_emitted=["allow", "modify"],
        entrypoint="tests:EmailRedactor",
        capabilities={"emits_modify": True},
    )
)


@pytest.fixture
def ctx():
    return PluginContext(http=httpx.AsyncClient(), secrets=EnvSecretReader())


async def test_good_guardrail_passes(ctx):
    report = await run_conformance(EmailRedactor(MANIFEST, ctx), {})
    failed = [c for c in report.checks if not c.passed and c.level == "MUST"]
    assert report.passed, failed


async def test_leaky_guardrail_fails(ctx):
    report = await run_conformance(Leaky(MANIFEST, ctx), {})
    assert not report.passed
    assert any("no raw sensitive values" in c.name and not c.passed for c in report.checks)


async def test_bad_config_fails_fast(ctx):
    report = await run_conformance(EmailRedactor(MANIFEST, ctx), {"replacement": 5})
    assert not report.passed
