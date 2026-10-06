"""Playground: send a real agent request through a gateway from the console.

Simulate is a dry run: no identity binding, session risk, decision table, review queue or audit.
The playground is the enforcement path itself. The control plane relays the request, with an
agent's gateway key (`gk_...`), to the gateway's public `POST /v1/guard/{stage}`, so the gateway
does everything it does for an agent: authenticates the key, scores risk with session state,
asks OPA, runs the guardrails and advisors, applies the decision table, files reviews, and writes
the audit record. Use it to check a configuration end to end, or to demo the platform.

Rules:
- Off unless the environment is in `PLAYGROUND_ENVIRONMENTS` (Compose: dev). Every request is
  real traffic in that environment: it counts toward the agent's session and trust history.
- The caller needs `catalog:write` on the key's tenant (the people who can mint keys anyway).
- The key is checked against the catalog (active, not expired, allowed in this environment)
  before anything is sent, and is never stored or logged. The change log records who sent what
  (stage, agent, decision), never the payload.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from guardrail_sdk.api import GuardRequest
from guardrail_sdk.models import Stage

from ..domain.rbac import Forbidden, Permission, Principal
from ..domain.records import ApiKeyRecord, utcnow
from ..errors import ValidationFailed
from .catalog import hash_key
from .context import Ctx
from .simulation import SimulationUnavailable

PLAYGROUND_STAGES = frozenset({Stage.INPUT, Stage.RETRIEVAL, Stage.TOOL, Stage.OUTPUT})
_ESCALATION_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class PlaygroundService:
    def __init__(
        self,
        ctx: Ctx,
        http: httpx.AsyncClient,
        *,
        environments: frozenset[str] = frozenset(),
        gateway_urls: dict[str, str] | None = None,
        default_gateway_url: str | None = None,
    ) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.http = http
        self.environments = environments
        self.gateway_urls = {k: v.rstrip("/") for k, v in (gateway_urls or {}).items()}
        self.default_gateway_url = default_gateway_url.rstrip("/") if default_gateway_url else None

    def gateway_for(self, environment: str) -> str | None:
        return self.gateway_urls.get(environment) or self.default_gateway_url

    def enabled_environments(self) -> list[str]:
        return sorted(e for e in self.environments if self.gateway_for(e))

    def _gateway(self, environment: str) -> str:
        if environment not in self.environments:
            raise Forbidden(f"the playground is not enabled for {environment} (PLAYGROUND_ENVIRONMENTS)")
        url = self.gateway_for(environment)
        if url is None:
            raise SimulationUnavailable(f"no gateway URL is configured for {environment}")
        return url

    async def _key(self, p: Principal, raw: str, environment: str) -> ApiKeyRecord:
        if not raw.startswith("gk_"):
            raise ValidationFailed("gateway_key must be an agent's gateway key (gk_...)")
        digest = hash_key(raw)
        key = next((k for k in await self.store.list_api_keys(None) if k.key_hash == digest), None)
        if key is None:
            raise ValidationFailed("unknown gateway key")
        # Tenant check first, so a key from another tenant says nothing more about itself.
        p.require(Permission.CATALOG_WRITE, key.tenant_id)
        if not key.is_active or key.revoked_at is not None:
            raise ValidationFailed("this gateway key is revoked")
        if key.expires_at is not None and key.expires_at <= utcnow():
            raise ValidationFailed("this gateway key has expired")
        if key.environments and environment not in key.environments:
            raise ValidationFailed(f"this gateway key is not valid in {environment}")
        return key

    async def send(
        self, p: Principal, *, environment: str, stage: Stage, gateway_key: str, request: GuardRequest
    ) -> dict[str, Any]:
        if stage not in PLAYGROUND_STAGES:
            raise ValidationFailed(f"the playground sends input, retrieval, tool or output requests, not {stage.value}")
        url = self._gateway(environment)
        key = await self._key(p, gateway_key, environment)
        resp = await self._call("POST", f"{url}/v1/guard/{stage.value}", gateway_key, request.model_dump(mode="json"))
        body = _json(resp)
        await self.ctx.log(
            "playground",
            str(body.get("request_id") or "-"),
            "send",
            p.actor,
            after={
                "environment": environment,
                "tenant_id": key.tenant_id,
                "key_id": key.id,
                "stage": stage.value,
                "agent_id": request.agent_id,
                "action": request.action,
                "status": resp.status_code,
                "decision": body.get("decision"),
                "outcome": body.get("outcome"),
            },
        )
        return _out(environment, key, resp, body)

    async def escalation(
        self, p: Principal, *, environment: str, gateway_key: str, escalation_id: str
    ) -> dict[str, Any]:
        """What the agent sees when it polls a held request (`GET /v1/escalations/{id}`)."""
        if not _ESCALATION_ID.match(escalation_id):
            raise ValidationFailed("invalid escalation id")
        url = self._gateway(environment)
        key = await self._key(p, gateway_key, environment)
        resp = await self._call("GET", f"{url}/v1/escalations/{escalation_id}", gateway_key, None)
        return _out(environment, key, resp, _json(resp))

    async def _call(self, method: str, url: str, key: str, body: dict[str, Any] | None) -> httpx.Response:
        try:
            return await self.http.request(method, url, json=body, headers={"X-API-Key": key})
        except httpx.HTTPError as exc:
            raise SimulationUnavailable(f"gateway is unreachable ({exc.__class__.__name__})", 502) from exc


def _out(environment: str, key: ApiKeyRecord, resp: httpx.Response, body: dict[str, Any]) -> dict[str, Any]:
    if not body and resp.status_code >= 500:
        raise SimulationUnavailable(f"gateway answered HTTP {resp.status_code}", 502)
    return {
        "environment": environment,
        "tenant_id": key.tenant_id,
        "key": {"id": key.id, "name": key.name, "prefix": key.prefix, "agent_id": key.agent_id},
        "status": resp.status_code,
        "retry_after": resp.headers.get("Retry-After"),
        "response": body,
    }


def _json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}
