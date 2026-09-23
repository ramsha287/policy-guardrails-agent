"""OPA client. Fail-closed: if OPA is unreachable or returns garbage, the answer is DENY."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PolicyDecision:
    allow: bool
    reason: str
    obligations: list[str] = field(default_factory=list)
    error: str | None = None


class PolicyEngine(Protocol):
    async def evaluate(self, policy_input: dict[str, Any]) -> PolicyDecision: ...


class OpaClient:
    def __init__(self, http: httpx.AsyncClient, base_url: str, decision_path: str, timeout_ms: int) -> None:
        self._http = http
        self._url = base_url.rstrip("/") + decision_path
        self._timeout = timeout_ms / 1000

    async def evaluate(self, policy_input: dict[str, Any]) -> PolicyDecision:
        try:
            resp = await self._http.post(self._url, json={"input": policy_input}, timeout=self._timeout)
            resp.raise_for_status()
            result = resp.json().get("result")
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("OPA evaluation failed, denying: %s", exc.__class__.__name__)
            return PolicyDecision(False, "policy engine unavailable (fail-closed)", error=exc.__class__.__name__)
        if not isinstance(result, dict) or not isinstance(result.get("allow"), bool):
            logger.error("OPA returned no decision document at %s, denying", self._url)
            return PolicyDecision(False, "policy engine returned no decision (fail-closed)", error="no_result")
        obligations = [o for o in result.get("obligations", []) if isinstance(o, str)]
        return PolicyDecision(result["allow"], str(result.get("reason") or ""), sorted(set(obligations)))

    async def healthy(self) -> bool:
        try:
            base = self._url.split("/v1/")[0]
            resp = await self._http.get(base + "/health", timeout=1.0)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False
