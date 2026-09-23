"""ai-gateway-pii: adapter from the Guardrail interface to the instant-redaction-service.

Calls POST /ai-gateway/redact/api/text?include_findings=true for each text segment and maps
the answer to ALLOW / MODIFY / BLOCK. Redaction logic stays in Presidio inside ai-gateway;
the ai-gateway project decides entities, custom patterns and replace/mask/hash.
"""

from __future__ import annotations

import asyncio
from typing import Literal
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardrail_sdk import (
    Decision,
    Finding,
    Guardrail,
    GuardrailResult,
    Payload,
    SecurityContext,
    Stage,
)

TEXT_PATH = "/ai-gateway/redact/api/text"
READY_PATH = "/ai-gateway/redact/api/ready"

Role = Literal["system", "user", "assistant", "tool"]


class StageOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    on_detect: Literal["modify", "block", "allow"] = "modify"
    block_entities: list[str] = Field(default_factory=list)
    scan_roles: list[Role] | None = None


class AiGatewayPiiConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    base_url: str | None = None
    input: StageOptions = Field(default_factory=lambda: StageOptions(scan_roles=["user"]))
    output: StageOptions = Field(default_factory=lambda: StageOptions(scan_roles=["assistant"]))

    @field_validator("project_id")
    @classmethod
    def _uuid(cls, v: str) -> str:
        UUID(v)
        return v


class AiGatewayError(RuntimeError):
    """ai-gateway returned an error or an unexpected response; the engine applies failure_mode."""


class _Detection(BaseModel):
    location: str
    redacted_text: str
    findings: list[Finding]


class AiGatewayPiiGuardrail(Guardrail):
    config_model = AiGatewayPiiConfig
    config: AiGatewayPiiConfig

    @property
    def _base(self) -> str:
        assert self.manifest.remote is not None
        return (self.config.base_url or self.manifest.remote.endpoint).rstrip("/")

    def _headers(self, ctx: SecurityContext | None) -> dict[str, str]:
        assert self.manifest.remote is not None
        headers: dict[str, str] = {}
        ref = self.manifest.remote.api_key_ref
        key = self.ctx.secrets.get(ref) if ref else None
        if key:
            headers["X-API-Key"] = key
        if ctx is not None:
            headers["X-Request-ID"] = ctx.request_id
            headers["traceparent"] = f"00-{ctx.trace_id}-{'0' * 15}1-01"
        return headers

    def _options(self, stage: Stage) -> StageOptions:
        opts = self.config.input if stage == Stage.INPUT else self.config.output
        if opts.scan_roles is None:
            default: list[Role] = ["user"] if stage == Stage.INPUT else ["assistant"]
            opts = opts.model_copy(update={"scan_roles": default})
        return opts

    async def _detect(self, ctx: SecurityContext, location: str, text: str) -> _Detection:
        if not text.strip():  # ai-gateway rejects blank text; nothing to find anyway
            return _Detection(location=location, redacted_text=text, findings=[])
        try:
            resp = await self.ctx.http.post(
                f"{self._base}{TEXT_PATH}",
                params={"include_findings": "true"},
                json={"text": text, "project_id": self.config.project_id},
                headers=self._headers(ctx),
            )
        except httpx.HTTPError as exc:
            raise AiGatewayError(f"ai-gateway unreachable ({exc.__class__.__name__})") from exc
        if resp.status_code != 200:
            # Never echo the response body: it could contain the submitted text.
            raise AiGatewayError(f"ai-gateway returned HTTP {resp.status_code}")
        body = resp.json()
        if "findings" not in body or "redacted_text" not in body:
            raise AiGatewayError("ai-gateway response has no findings; service must support include_findings")
        findings = [
            Finding(
                type=str(f["entity_type"]),
                score=max(0.0, min(1.0, float(f.get("score", 1.0)))),
                start=f.get("start"),
                end=f.get("end"),
                location=location,
            )
            for f in body["findings"]
        ]
        return _Detection(location=location, redacted_text=body["redacted_text"], findings=findings)

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        if payload.stage not in (Stage.INPUT, Stage.OUTPUT):
            raise AiGatewayError(f"stage {payload.stage.value} is not supported by {self.manifest.key}")
        opts = self._options(payload.stage)

        jobs: list[tuple[str, str]] = []
        if payload.text is not None:
            jobs.append(("text", payload.text))
        for i, m in enumerate(payload.messages or []):
            if m.role in (opts.scan_roles or []):
                jobs.append((f"messages[{i}]", m.content))

        detections = await asyncio.gather(*(self._detect(context, loc, txt) for loc, txt in jobs))
        findings = [f for d in detections for f in d.findings]
        if not findings:
            return GuardrailResult(decision=Decision.ALLOW, reason="no PII detected", risk_score=0)

        types = sorted({f.type for f in findings})
        summary = f"{len(findings)} PII finding(s): {', '.join(types)}"
        blocked = sorted(set(types) & set(opts.block_entities))
        if blocked:
            return GuardrailResult(
                decision=Decision.BLOCK,
                reason=f"blocked entity type(s) present: {', '.join(blocked)}",
                risk_score=90,
                findings=findings,
            )
        risk = min(80, 30 + 10 * len(findings))
        if opts.on_detect == "block":
            return GuardrailResult(decision=Decision.BLOCK, reason=summary, risk_score=risk, findings=findings)
        if opts.on_detect == "allow":
            return GuardrailResult(
                decision=Decision.ALLOW, reason=f"{summary} (allowed by config)", risk_score=risk, findings=findings
            )

        data = payload.model_dump(mode="python")
        for d in detections:
            if not d.findings:
                continue
            if d.location == "text":
                data["text"] = d.redacted_text
            else:
                idx = int(d.location[len("messages[") : -1])
                data["messages"][idx]["content"] = d.redacted_text
        return GuardrailResult(
            decision=Decision.MODIFY,
            reason=f"redacted {summary}",
            risk_score=risk,
            findings=findings,
            modified_payload=Payload.model_validate(data),
        )

    async def health(self) -> bool:
        try:
            resp = await self.ctx.http.get(f"{self._base}{READY_PATH}", timeout=2.0)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False
