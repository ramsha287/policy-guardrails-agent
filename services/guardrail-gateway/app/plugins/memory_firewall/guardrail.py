"""`memory-firewall`: retrieved agent memory checked by the Memory Firewall service.

Retrieval stage only. One POST /v1/memory/inspect per request with every non-blank chunk:

    id          "<tenant>/<agent>/<chunk id>" (provenance records are per tenant and agent)
    source      chunk.metadata[source_field], else chunk.source when it is a known label, else
                `default_source`, else "unlabeled" (the service treats unknown labels as untrusted)
    writer      chunk.metadata[writer_field], else "unknown"
    authorized  writer matches `authorized_writers` (glob); null config = writer gate off

The service answers per chunk: admitted, or quarantined with the library's reason (unauthorized
writer, untrusted source), plus the scan's injection-text findings. `on_quarantine` and
`on_injection_text` turn those into dropped chunks (MODIFY), a held request or a block; strongest
wins. The service URL and key are operator settings (MEMORY_FIREWALL_URL, MEMORY_FIREWALL_API_KEY),
not assignment config, so an editor can't send memory or the key to another host.
"""

from __future__ import annotations

import fnmatch
from collections import Counter
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.plugins.common.textwalk import rewrite
from guardrail_sdk import Decision, Finding, Guardrail, GuardrailResult, Payload, SecurityContext, Stage

INSPECT_PATH = "/v1/memory/inspect"
READY_PATH = "/ready"
SOURCES = ("system", "user", "tool", "web")
Action = Literal["drop_chunk", "escalate", "block"]


class MemoryFirewallConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_field: str = Field("source_type", min_length=1, max_length=64)
    writer_field: str = Field("writer", min_length=1, max_length=64)
    default_source: Literal["system", "user", "tool", "web"] | None = None
    authorized_writers: list[str] | None = Field(default=None, max_length=100)
    scan_text: bool = True
    on_quarantine: Action = "drop_chunk"
    on_injection_text: Literal["drop_chunk", "escalate", "block", "allow"] = "drop_chunk"


class MemoryFirewallError(RuntimeError):
    """The service is unreachable or answered unexpectedly; the engine applies failure_mode."""


_DECISION = {"drop_chunk": Decision.MODIFY, "escalate": Decision.ESCALATE, "block": Decision.BLOCK}
_RANK = {Decision.ALLOW: 0, Decision.MODIFY: 1, Decision.ESCALATE: 2, Decision.BLOCK: 3}


class MemoryFirewallGuardrail(Guardrail):
    config_model = MemoryFirewallConfig
    config: MemoryFirewallConfig

    @property
    def _base(self) -> str:
        assert self.manifest.remote is not None
        return (self.ctx.secrets.get("env://MEMORY_FIREWALL_URL") or self.manifest.remote.endpoint).rstrip("/")

    def _headers(self, ctx: SecurityContext | None = None) -> dict[str, str]:
        assert self.manifest.remote is not None
        ref = self.manifest.remote.api_key_ref
        key = self.ctx.secrets.get(ref) if ref else None
        headers = {"X-API-Key": key} if key else {}
        if ctx is not None:
            headers["X-Request-ID"] = ctx.request_id
        return headers

    def _label(self, chunk: Any) -> str:
        label = chunk.metadata.get(self.config.source_field)
        if isinstance(label, str) and label:
            return label
        if chunk.source in SOURCES:
            return str(chunk.source)
        return self.config.default_source or "unlabeled"

    def _writer(self, chunk: Any) -> str:
        writer = chunk.metadata.get(self.config.writer_field)
        return writer[:200] if isinstance(writer, str) and writer else "unknown"

    def _authorized(self, writer: str) -> bool:
        patterns = self.config.authorized_writers
        return patterns is None or any(fnmatch.fnmatchcase(writer, p) for p in patterns)

    async def _inspect(self, ctx: SecurityContext, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        try:
            resp = await self.ctx.http.post(
                f"{self._base}{INSPECT_PATH}",
                json={"items": items, "scan": self.config.scan_text},
                headers=self._headers(ctx),
            )
        except httpx.HTTPError as exc:
            raise MemoryFirewallError(f"memory-firewall unreachable ({exc.__class__.__name__})") from exc
        if resp.status_code != 200:
            # Never echo the response body.
            raise MemoryFirewallError(f"memory-firewall returned HTTP {resp.status_code}")
        results = resp.json().get("results")
        if not isinstance(results, list) or len(results) != len(items):
            raise MemoryFirewallError("memory-firewall returned an unexpected body")
        return results

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        if payload.stage != Stage.RETRIEVAL:
            raise MemoryFirewallError(f"stage {payload.stage.value} is not supported by {self.manifest.key}")
        chunks = payload.chunks or []
        positions = [i for i, c in enumerate(chunks) if c.text.strip()]
        if not positions:
            return GuardrailResult(decision=Decision.ALLOW, reason="no retrieved memory to check")
        items = []
        for i in positions:
            c = chunks[i]
            writer = self._writer(c)
            items.append(
                {
                    "id": f"{context.tenant_id}/{context.agent_id}/{c.id}"[:300],
                    "text": c.text,
                    "source": self._label(c)[:40],
                    "writer": writer,
                    "authorized": self._authorized(writer),
                }
            )
        results = await self._inspect(context, items)

        findings: list[Finding] = []
        reasons: Counter[str] = Counter()
        drop: set[int] = set()
        decision = Decision.ALLOW
        quarantined: list[str] = []
        flagged: list[str] = []
        for pos, r in zip(positions, results, strict=True):
            chunk = chunks[pos]
            location = f"chunks[{chunk.id}]"
            hit: Decision | None = None
            if not r.get("admitted", False):
                quarantined.append(chunk.id)
                reasons[str(r.get("quarantine_reason") or "quarantined")] += 1
                findings.append(Finding(type="MEMORY_QUARANTINED", score=1.0, location=location))
                hit = _DECISION[self.config.on_quarantine]
            scan = [str(s) for s in r.get("scan_findings") or []]
            if scan:
                flagged.append(chunk.id)
                reasons.update(s.split(":", 1)[0] for s in scan)
                findings.append(Finding(type="MEMORY_INJECTION_TEXT", score=0.9, location=location))
                if self.config.on_injection_text != "allow":
                    act = _DECISION[self.config.on_injection_text]
                    hit = act if hit is None or _RANK[act] > _RANK[hit] else hit
            if hit is not None:
                if hit == Decision.MODIFY:
                    drop.add(pos)
                if _RANK[hit] > _RANK[decision]:
                    decision = hit

        meta: dict[str, Any] = {"quarantined": quarantined, "flagged": flagged, "reasons": dict(reasons)}
        if not findings:
            return GuardrailResult(
                decision=Decision.ALLOW, reason=f"{len(items)} memory chunk(s) verified", metadata=meta
            )
        risk = min(90, 40 + 10 * len(findings))
        summary = f"{len(quarantined)} quarantined, {len(flagged)} with instruction-like text"
        if decision == Decision.ALLOW:
            return GuardrailResult(
                decision=Decision.ALLOW,
                reason=f"{summary} (allowed by config)",
                risk_score=risk,
                findings=findings,
                metadata=meta,
            )
        if decision == Decision.MODIFY:
            meta["dropped_chunks"] = [chunks[i].id for i in sorted(drop)]
            return GuardrailResult(
                decision=Decision.MODIFY,
                reason=f"dropped {len(drop)} memory chunk(s): {summary}",
                risk_score=risk,
                findings=findings,
                metadata=meta,
                modified_payload=rewrite(payload, {}, drop_chunks=frozenset(drop)),
            )
        verb = "untrusted memory" if decision == Decision.BLOCK else "possibly poisoned memory"
        return GuardrailResult(
            decision=decision, reason=f"{verb}: {summary}", risk_score=risk, findings=findings, metadata=meta
        )

    async def health(self) -> bool:
        try:
            resp = await self.ctx.http.get(f"{self._base}{READY_PATH}", timeout=2.0)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False
