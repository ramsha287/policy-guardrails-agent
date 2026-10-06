"""`content-moderation`: harmful content (harassment, hate, violence, self-harm, sexual content)
in prompts and answers, through an OpenAI-compatible moderation endpoint.

    POST {base}/moderations  {"model": "...", "input": ["text", ...]}
    200  {"results": [{"flagged": bool, "categories": {...}, "category_scores": {...}}, ...]}

That is OpenAI's moderation API, and the same shape is served by self-hosted gateways in front of
open models (Llama Guard and similar), which keeps the text in your own network. The endpoint is
set by the operator (MODERATION_BASE_URL, default https://api.openai.com/v1) and the key comes from
MODERATION_API_KEY; neither can be changed from an assignment's config, so an editor can't point
the key at another host.

Each scanned text goes out as one array item; results map back to locations. Categories in
`block_categories` block; any other flagged category escalates (or blocks/allows, see
`on_flagged`). `thresholds` let you flag on scores instead of the endpoint's own booleans.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.plugins.common.textwalk import walk
from guardrail_sdk import Decision, Finding, Guardrail, GuardrailResult, Payload, SecurityContext

MAX_ITEMS = 32  # texts per request
MAX_CHARS = 32_000  # per text; longer texts are split into pieces, each moderated
SCAN_LIMIT = 1_100_000  # characters per payload; above max_payload_kb, so truncation means "too large"


class ModerationError(RuntimeError):
    pass


class ModerationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str = Field("omni-moderation-latest", min_length=1, max_length=100)
    block_categories: list[str] = Field(default_factory=lambda: ["sexual/minors"])
    on_flagged: Literal["escalate", "block", "allow"] = "escalate"
    # category -> score at or above which it counts as flagged (overrides the endpoint's boolean)
    thresholds: dict[str, Annotated[float, Field(ge=0.0, le=1.0)]] = Field(default_factory=dict)
    scan_roles: list[Literal["system", "user", "assistant", "tool"]] = Field(
        default_factory=lambda: ["user", "assistant"]
    )


def _finding_type(category: str) -> str:
    return "MODERATION_" + "".join(ch if ch.isalnum() else "_" for ch in category.upper())


class ContentModerationGuardrail(Guardrail):
    config_model = ModerationConfig
    config: ModerationConfig

    @property
    def _base(self) -> str:
        assert self.manifest.remote is not None
        return (self.ctx.secrets.get("env://MODERATION_BASE_URL") or self.manifest.remote.endpoint).rstrip("/")

    def _headers(self) -> dict[str, str]:
        assert self.manifest.remote is not None
        ref = self.manifest.remote.api_key_ref
        key = self.ctx.secrets.get(ref) if ref else None
        return {"Authorization": f"Bearer {key}"} if key else {}

    async def _moderate(self, texts: list[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for i in range(0, len(texts), MAX_ITEMS):
            batch = texts[i : i + MAX_ITEMS]
            try:
                resp = await self.ctx.http.post(
                    f"{self._base}/moderations",
                    json={"model": self.config.model, "input": batch},
                    headers=self._headers(),
                )
            except httpx.HTTPError as exc:
                raise ModerationError(f"moderation endpoint unreachable ({exc.__class__.__name__})") from exc
            if resp.status_code != 200:
                raise ModerationError(f"moderation endpoint returned HTTP {resp.status_code}")
            try:
                body = resp.json()
            except ValueError as exc:
                raise ModerationError("moderation endpoint returned invalid JSON") from exc
            results = body.get("results") if isinstance(body, dict) else None
            if not isinstance(results, list) or len(results) != len(batch):
                raise ModerationError("moderation endpoint returned an unexpected body")
            out.extend(r if isinstance(r, dict) else {} for r in results)
        return out

    def _flagged(self, result: dict[str, Any]) -> dict[str, float]:
        """category -> score for every category that counts as flagged."""
        cats = result.get("categories") or {}
        scores = result.get("category_scores") or {}
        flagged: dict[str, float] = {}
        for name in set(cats) | set(scores):
            score = float(scores.get(name) or 0.0)
            threshold = self.config.thresholds.get(name)
            hit = score >= threshold if threshold is not None else bool(cats.get(name))
            if hit:
                flagged[name] = max(0.0, min(1.0, score))
        return flagged

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        w = walk(
            payload, roles=frozenset(self.config.scan_roles), tool_arguments=False, tool_result=False, limit=SCAN_LIMIT
        )
        if w.truncated:
            return GuardrailResult(
                decision=Decision.BLOCK,
                reason="too large to moderate fully (fail closed)",
                metadata={"truncated": True},
            )
        spans = [s for s in w.spans if s.text.strip()]
        if not spans:
            return GuardrailResult(decision=Decision.ALLOW, reason="nothing to moderate")
        # Every piece of every text is moderated; a span is flagged if any of its pieces is.
        pieces = [(i, s.text[k : k + MAX_CHARS]) for i, s in enumerate(spans) for k in range(0, len(s.text), MAX_CHARS)]
        results = await self._moderate([text for _, text in pieces])
        per_span: list[dict[str, float]] = [{} for _ in spans]
        for (i, _), result in zip(pieces, results, strict=True):
            for name, score in self._flagged(result).items():
                per_span[i][name] = max(per_span[i].get(name, 0.0), score)
        findings: list[Finding] = []
        categories: set[str] = set()
        top = 0.0
        for span, flagged in zip(spans, per_span, strict=True):
            for name, score in sorted(flagged.items()):
                categories.add(name)
                top = max(top, score)
                findings.append(Finding(type=_finding_type(name), score=score, location=span.location))
        if not findings:
            return GuardrailResult(decision=Decision.ALLOW, reason="no moderation category flagged")
        names = sorted(categories)
        meta = {"categories": names}
        risk = max(50, int(top * 100))
        if categories & set(self.config.block_categories) or self.config.on_flagged == "block":
            decision = Decision.BLOCK
        elif self.config.on_flagged == "escalate":
            decision = Decision.ESCALATE
        else:
            decision = Decision.ALLOW
        return GuardrailResult(
            decision=decision, reason=f"flagged: {', '.join(names)}", risk_score=risk, findings=findings, metadata=meta
        )
