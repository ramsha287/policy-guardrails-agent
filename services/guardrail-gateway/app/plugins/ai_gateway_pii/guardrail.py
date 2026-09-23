"""ai-gateway-pii: adapter from the Guardrail interface to the instant-redaction-service.

Stage          ai-gateway call                                 Outcome
input/output   POST /text?include_findings=true per segment    redact text / messages, or block
retrieval      POST /text/batch (<=100 chunks per call)        redact chunks, drop risky chunks, or block
tool           POST /json?include_findings=true                redact arguments/result, block PII leaving
                                                                the trust boundary via external tools

Redaction logic stays in Presidio inside ai-gateway; the ai-gateway project decides entities,
custom patterns and replace/mask/hash. Manifest 1.0.0 covers input/output, 1.1.0 all four.
"""

from __future__ import annotations

import asyncio
import fnmatch
from typing import Any, Literal
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
BATCH_PATH = "/ai-gateway/redact/api/text/batch"
JSON_PATH = "/ai-gateway/redact/api/json"
READY_PATH = "/ai-gateway/redact/api/ready"
MAX_BATCH = 100

Role = Literal["system", "user", "assistant", "tool"]
OnDetect = Literal["modify", "block", "allow"]


class StageOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    on_detect: OnDetect = "modify"
    block_entities: list[str] = Field(default_factory=list)
    scan_roles: list[Role] | None = None


class RetrievalOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    on_detect: OnDetect = "modify"
    block_entities: list[str] = Field(default_factory=list)  # chunks containing these are dropped
    drop_chunk_if_entities_gt: int | None = Field(default=None, ge=0)


class ToolPartOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    on_detect: OnDetect = "modify"
    block_entities: list[str] = Field(default_factory=list)


class ToolOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    arguments: ToolPartOptions = Field(default_factory=ToolPartOptions)
    result: ToolPartOptions = Field(default_factory=ToolPartOptions)
    external_tools: list[str] = Field(default_factory=list)
    external_on_detect: Literal["block", "modify"] = "block"


class AiGatewayPiiConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    base_url: str | None = None
    input: StageOptions = Field(default_factory=lambda: StageOptions(scan_roles=["user"]))
    output: StageOptions = Field(default_factory=lambda: StageOptions(scan_roles=["assistant"]))
    retrieval: RetrievalOptions = Field(default_factory=RetrievalOptions)
    tool: ToolOptions = Field(default_factory=ToolOptions)

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


def _risk(findings: list[Finding]) -> int:
    return min(80, 30 + 10 * len(findings)) if findings else 0


def _types(findings: list[Finding]) -> list[str]:
    return sorted({f.type for f in findings})


def _summary(findings: list[Finding]) -> str:
    return f"{len(findings)} PII finding(s): {', '.join(_types(findings))}"


class AiGatewayPiiGuardrail(Guardrail):
    config_model = AiGatewayPiiConfig
    config: AiGatewayPiiConfig

    # ---- HTTP helpers -------------------------------------------------------------------

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

    async def _post(self, ctx: SecurityContext, path: str, body: dict[str, Any], **params: str) -> dict[str, Any]:
        try:
            resp = await self.ctx.http.post(
                f"{self._base}{path}", params=params or None, json=body, headers=self._headers(ctx)
            )
        except httpx.HTTPError as exc:
            raise AiGatewayError(f"ai-gateway unreachable ({exc.__class__.__name__})") from exc
        if resp.status_code != 200:
            # Never echo the response body: it could contain the submitted text.
            raise AiGatewayError(f"ai-gateway returned HTTP {resp.status_code} for {path}")
        data = resp.json()
        if not isinstance(data, dict):
            raise AiGatewayError(f"ai-gateway returned an unexpected body for {path}")
        return data

    @staticmethod
    def _findings(raw: list[dict[str, Any]], location: str) -> list[Finding]:
        return [
            Finding(
                type=str(f["entity_type"]),
                score=max(0.0, min(1.0, float(f.get("score", 1.0)))),
                start=f.get("start"),
                end=f.get("end"),
                location=location,
            )
            for f in raw
        ]

    async def _detect(self, ctx: SecurityContext, location: str, text: str) -> _Detection:
        if not text.strip():  # ai-gateway rejects blank text; nothing to find anyway
            return _Detection(location=location, redacted_text=text, findings=[])
        body = await self._post(
            ctx, TEXT_PATH, {"text": text, "project_id": self.config.project_id}, include_findings="true"
        )
        if "findings" not in body or "redacted_text" not in body:
            raise AiGatewayError("ai-gateway response has no findings; service must support include_findings")
        return _Detection(
            location=location, redacted_text=body["redacted_text"], findings=self._findings(body["findings"], location)
        )

    # ---- entry point --------------------------------------------------------------------

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        if payload.stage not in self.stages:
            raise AiGatewayError(f"stage {payload.stage.value} is not supported by {self.manifest.key}")
        if payload.stage in (Stage.INPUT, Stage.OUTPUT):
            return await self._text_stage(context, payload)
        if payload.stage == Stage.RETRIEVAL:
            return await self._retrieval_stage(context, payload)
        if payload.stage == Stage.TOOL:
            return await self._tool_stage(context, payload)
        raise AiGatewayError(f"stage {payload.stage.value} is not supported by {self.manifest.key}")

    # ---- input / output -----------------------------------------------------------------

    def _options(self, stage: Stage) -> StageOptions:
        opts = self.config.input if stage == Stage.INPUT else self.config.output
        if opts.scan_roles is None:
            default: list[Role] = ["user"] if stage == Stage.INPUT else ["assistant"]
            opts = opts.model_copy(update={"scan_roles": default})
        return opts

    async def _text_stage(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
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

        blocked = sorted(set(_types(findings)) & set(opts.block_entities))
        if blocked:
            return GuardrailResult(
                decision=Decision.BLOCK,
                reason=f"blocked entity type(s) present: {', '.join(blocked)}",
                risk_score=90,
                findings=findings,
            )
        if opts.on_detect == "block":
            return GuardrailResult(
                decision=Decision.BLOCK, reason=_summary(findings), risk_score=_risk(findings), findings=findings
            )
        if opts.on_detect == "allow":
            return GuardrailResult(
                decision=Decision.ALLOW,
                reason=f"{_summary(findings)} (allowed by config)",
                risk_score=_risk(findings),
                findings=findings,
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
            reason=f"redacted {_summary(findings)}",
            risk_score=_risk(findings),
            findings=findings,
            modified_payload=Payload.model_validate(data),
        )

    # ---- retrieval ----------------------------------------------------------------------

    async def _retrieval_stage(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        opts = self.config.retrieval
        chunks = payload.chunks or []
        # Internal ids are list positions, so duplicate chunk ids from the caller are harmless.
        items = [{"id": str(i), "text": c.text} for i, c in enumerate(chunks) if c.text.strip()]
        batches = [items[i : i + MAX_BATCH] for i in range(0, len(items), MAX_BATCH)]
        responses = await asyncio.gather(
            *(self._post(context, BATCH_PATH, {"project_id": self.config.project_id, "items": b}) for b in batches)
        )
        per_chunk: dict[int, tuple[str, list[Finding]]] = {}
        for resp in responses:
            if not isinstance(resp.get("results"), list):
                raise AiGatewayError("ai-gateway /text/batch response has no results; service must support batch")
            for r in resp["results"]:
                idx = int(r["id"])
                per_chunk[idx] = (r["redacted_text"], self._findings(r["findings"], f"chunks[{chunks[idx].id}]"))

        findings = [f for _, fs in per_chunk.values() for f in fs]
        if not findings:
            return GuardrailResult(decision=Decision.ALLOW, reason="no PII detected in retrieved chunks")
        if opts.on_detect == "block":
            return GuardrailResult(
                decision=Decision.BLOCK, reason=_summary(findings), risk_score=_risk(findings), findings=findings
            )
        if opts.on_detect == "allow":
            return GuardrailResult(
                decision=Decision.ALLOW,
                reason=f"{_summary(findings)} (allowed by config)",
                risk_score=_risk(findings),
                findings=findings,
            )

        kept: list[dict[str, Any]] = []
        dropped: list[str] = []
        for i, chunk in enumerate(chunks):
            redacted, fs = per_chunk.get(i, (chunk.text, []))
            too_many = opts.drop_chunk_if_entities_gt is not None and len(fs) > opts.drop_chunk_if_entities_gt
            if too_many or set(_types(fs)) & set(opts.block_entities):
                dropped.append(chunk.id)
                continue
            data = chunk.model_dump(mode="python")
            if fs:
                data["text"] = redacted
            kept.append(data)

        reason = f"redacted {_summary(findings)}"
        if dropped:
            reason += f"; dropped {len(dropped)} chunk(s)"
        return GuardrailResult(
            decision=Decision.MODIFY,
            reason=reason,
            risk_score=_risk(findings),
            findings=findings,
            metadata={"dropped_chunks": dropped},
            modified_payload=Payload.model_validate({**payload.model_dump(mode="python"), "chunks": kept}),
        )

    # ---- tool ---------------------------------------------------------------------------

    async def _scan_json(self, ctx: SecurityContext, data: Any, prefix: str) -> tuple[Any, list[Finding]]:
        body = await self._post(
            ctx, JSON_PATH, {"project_id": self.config.project_id, "data": data}, include_findings="true"
        )
        if "data" not in body or "findings" not in body:
            raise AiGatewayError("ai-gateway /json response has no findings; service must support /json")
        findings: list[Finding] = []
        for f in body["findings"]:
            path = str(f.get("path", "$"))
            findings.extend(self._findings([f], prefix + path[1:]))
        return body["data"], findings

    async def _tool_stage(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        opts = self.config.tool
        call = payload.tool_call
        assert call is not None
        external = any(fnmatch.fnmatchcase(call.name, p) for p in opts.external_tools)

        jobs: dict[str, Any] = {}
        if call.arguments:
            jobs["arguments"] = self._scan_json(context, call.arguments, "tool_call.arguments")
        if call.result is not None:
            jobs["result"] = self._scan_json(context, call.result, "tool_call.result")
        outcomes = dict(zip(jobs, await asyncio.gather(*jobs.values()), strict=True))

        all_findings = [f for _, fs in outcomes.values() for f in fs]
        if not all_findings:
            return GuardrailResult(decision=Decision.ALLOW, reason="no PII detected in tool call")

        new_call = call.model_dump(mode="python")
        modified = False
        for part in ("arguments", "result"):
            if part not in outcomes or not outcomes[part][1]:
                continue
            redacted, fs = outcomes[part]
            part_opts: ToolPartOptions = getattr(opts, part)
            on_detect: str = part_opts.on_detect
            if part == "arguments" and external:
                on_detect = opts.external_on_detect
            blocked = sorted(set(_types(fs)) & set(part_opts.block_entities))
            if blocked:
                return GuardrailResult(
                    decision=Decision.BLOCK,
                    reason=f"blocked entity type(s) in tool {part}: {', '.join(blocked)}",
                    risk_score=90,
                    findings=all_findings,
                )
            if on_detect == "block":
                where = f"arguments to external tool {call.name}" if part == "arguments" and external else part
                return GuardrailResult(
                    decision=Decision.BLOCK,
                    reason=f"PII in tool {where}: {', '.join(_types(fs))}",
                    risk_score=max(_risk(fs), 85 if external else 0),
                    findings=all_findings,
                )
            if on_detect == "modify":
                new_call[part] = redacted
                modified = True

        if not modified:
            return GuardrailResult(
                decision=Decision.ALLOW,
                reason=f"{_summary(all_findings)} (allowed by config)",
                risk_score=_risk(all_findings),
                findings=all_findings,
            )
        return GuardrailResult(
            decision=Decision.MODIFY,
            reason=f"redacted {_summary(all_findings)} in tool call",
            risk_score=_risk(all_findings),
            findings=all_findings,
            modified_payload=Payload.model_validate({**payload.model_dump(mode="python"), "tool_call": new_call}),
        )

    async def health(self) -> bool:
        try:
            resp = await self.ctx.http.get(f"{self._base}{READY_PATH}", timeout=2.0)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False
