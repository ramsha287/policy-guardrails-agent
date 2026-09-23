"""Agent-side client for the guardrail gateway (sidecar mode).

async with GuardClient("http://guardrail-gateway:8100", api_key, agent_id="research-agent") as guard:
    r = await guard.check_input("Summarise the account for jane@example.com", user_id="u1")
    if not r.allowed:
        return r.reason
    prompt = r.payload.text          # redacted when the decision was MODIFY
    answer = await llm(prompt)
    out = await guard.check_output(answer, user_id="u1")
    return out.payload.text if out.allowed else "Sorry, I can't share that."
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from .api import GuardPayloadIn, GuardRequest, GuardResponse
from .documents import EscalationStatus
from .models import Chunk, Message, Stage, ToolCall


class GuardrailGatewayError(RuntimeError):
    """Raised for transport errors and non-decision HTTP errors (401, 422, 5xx)."""

    def __init__(self, status_code: int | None, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class GuardClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        agent_id: str,
        timeout_seconds: float = 5.0,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._agent_id = agent_id
        self._headers = {"X-API-Key": api_key}
        self._own_http = http is None
        self._http = http or httpx.AsyncClient(timeout=timeout_seconds)

    async def __aenter__(self) -> GuardClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._own_http:
            await self._http.aclose()

    async def guard(
        self,
        stage: Stage | str,
        payload: GuardPayloadIn,
        *,
        action: str,
        request_id: str | None = None,
        **fields: Any,
    ) -> GuardResponse:
        stage = Stage(stage)
        body = GuardRequest(agent_id=self._agent_id, action=action, payload=payload, **fields)
        headers = dict(self._headers)
        if request_id:
            headers["X-Request-ID"] = request_id
        try:
            resp = await self._http.post(
                f"{self._base}/v1/guard/{stage.value}",
                json=body.model_dump(mode="json", exclude_none=True),
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise GuardrailGatewayError(None, f"guardrail gateway unreachable: {exc}") from exc
        # 200 = allow/modify/block, 202 = escalate, 403 = policy deny: all carry a GuardResponse.
        if resp.status_code in (200, 202, 403):
            try:
                return GuardResponse.model_validate(resp.json())
            except ValueError:
                pass
        raise GuardrailGatewayError(resp.status_code, resp.text[:500])

    async def get_escalation(self, escalation_id: str) -> EscalationStatus:
        try:
            resp = await self._http.get(f"{self._base}/v1/escalations/{escalation_id}", headers=self._headers)
        except httpx.HTTPError as exc:
            raise GuardrailGatewayError(None, f"guardrail gateway unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise GuardrailGatewayError(resp.status_code, resp.text[:500])
        return EscalationStatus.model_validate(resp.json())

    async def wait_for_escalation(
        self, escalation_id: str, *, timeout_seconds: float = 300.0, poll_seconds: float = 2.0
    ) -> EscalationStatus:
        """Poll until a reviewer decides or the review expires. On local timeout returns the pending status."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        while True:
            status = await self.get_escalation(escalation_id)
            if status.status != "pending" or loop.time() >= deadline:
                return status
            await asyncio.sleep(min(poll_seconds, max(0.0, deadline - loop.time())))

    async def check_input(self, text: str, *, action: str = "llm.chat", **fields: Any) -> GuardResponse:
        return await self.guard(Stage.INPUT, GuardPayloadIn(text=text), action=action, **fields)

    async def check_messages(
        self, messages: list[Message], *, stage: Stage = Stage.INPUT, action: str = "llm.chat", **fields: Any
    ) -> GuardResponse:
        return await self.guard(stage, GuardPayloadIn(messages=messages), action=action, **fields)

    async def check_output(self, text: str, *, action: str = "llm.chat", **fields: Any) -> GuardResponse:
        return await self.guard(Stage.OUTPUT, GuardPayloadIn(text=text), action=action, **fields)

    async def check_retrieval(
        self, chunks: list[Chunk], *, action: str = "retrieval.search", **fields: Any
    ) -> GuardResponse:
        return await self.guard(Stage.RETRIEVAL, GuardPayloadIn(chunks=chunks), action=action, **fields)

    async def check_tool(self, tool_call: ToolCall, **fields: Any) -> GuardResponse:
        return await self.guard(Stage.TOOL, GuardPayloadIn(tool_call=tool_call), action=tool_call.name, **fields)
