"""Generic remote guardrail: any service that speaks POST /evaluate + GET /health."""

from __future__ import annotations

import os
from typing import Any

import httpx

from .guardrail import Guardrail
from .models import GuardrailResult, Payload, SecurityContext


class EnvSecretReader:
    """Resolves `env://NAME` references. Other schemes (vault://, k8s://) plug in here later."""

    def get(self, ref: str) -> str | None:
        if ref.startswith("env://"):
            return os.environ.get(ref[len("env://") :])
        return None


class RemoteGuardrail(Guardrail):
    """Protocol:

    POST {endpoint}/evaluate  {"guardrail": {...}, "config": {...}, "context": {...}, "payload": {...}}
      -> GuardrailResult JSON
    GET  {endpoint}/health    -> 200 when ready
    """

    def _headers(self, context: SecurityContext | None = None) -> dict[str, str]:
        spec = self.manifest.remote
        assert spec is not None
        headers: dict[str, str] = {}
        if spec.auth == "api_key" and spec.api_key_ref:
            key = self.ctx.secrets.get(spec.api_key_ref)
            if key:
                headers["X-API-Key"] = key
        if context is not None:
            headers["X-Request-ID"] = context.request_id
            headers["traceparent"] = f"00-{context.trace_id}-{'0' * 15}1-01"
        return headers

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        spec = self.manifest.remote
        assert spec is not None
        body: dict[str, Any] = {
            "guardrail": {"id": self.id, "version": self.version},
            "config": self.config.model_dump(mode="json"),
            "context": context.model_dump(mode="json"),
            "payload": payload.model_dump(mode="json"),
        }
        resp = await self.ctx.http.post(
            spec.endpoint.rstrip("/") + "/evaluate",
            json=body,
            headers=self._headers(context),
            timeout=spec.timeout_ms / 1000,
        )
        resp.raise_for_status()
        return GuardrailResult.model_validate(resp.json())

    async def health(self) -> bool:
        spec = self.manifest.remote
        assert spec is not None
        try:
            resp = await self.ctx.http.get(spec.endpoint.rstrip("/") + "/health", headers=self._headers(), timeout=2.0)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False
