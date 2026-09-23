"""Agent hooks: call the guardrail gateway at each stage and get back the value that is safe to use.

Every hook returns the (possibly redacted) value, or raises `GuardrailBlocked`. Hooks never
return the original value after a MODIFY, so an agent cannot accidentally use unredacted data.

    hooks = GuardHooks(GuardClient(url, key, agent_id="research-agent"), user_id="u1", data_classification="PII")
    prompt = await hooks.before_llm(user_text)          # input stage
    docs   = await hooks.on_retrieval(chunks)           # retrieval stage
    args   = await hooks.before_tool("crm.lookup", {"email": "..."})    # tool stage, before the call
    result = await hooks.after_tool("crm.lookup", args, raw_result)     # tool stage, after the call
    answer = await hooks.after_llm(llm_text)            # output stage

`SyncGuardHooks` offers the same API for synchronous code (CrewAI tools, scripts).
"""

from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .api import GuardPayloadIn, GuardRequest, GuardResponse
from .client import GuardClient, GuardrailGatewayError
from .documents import EscalationStatus
from .models import Chunk, DataClassification, Decision, Message, Stage, ToolCall


class GuardrailBlocked(Exception):
    """The gateway blocked this step (guardrail BLOCK or policy DENY). `response` has the details."""

    def __init__(self, response: GuardResponse, reason: str | None = None) -> None:
        self.response = response
        self._reason = reason or response.reason
        super().__init__(f"{response.stage.value} blocked: {self._reason}")

    @property
    def reason(self) -> str:
        return self._reason


class GuardrailEscalated(GuardrailBlocked):
    """Held for human review. Poll `client.wait_for_escalation(escalation_id)` or retry later.

    Raised when the hooks are not configured to wait (`wait_for_review_seconds=0`), or when the
    wait ended with the review still pending.
    """

    @property
    def escalation_id(self) -> str | None:
        return self.response.escalation_id


@dataclass(frozen=True)
class GuardDefaults:
    """Request fields sent with every hook call. Use `with_context()` for per-request values."""

    user_id: str | None = None
    session_id: str | None = None
    data_classification: DataClassification = "INTERNAL"
    delegation_chain: tuple[str, ...] = ()
    llm_action: str = "llm.chat"
    retrieval_action: str = "retrieval.search"
    # > 0: when a step is escalated, poll for the reviewer's decision up to this long.
    wait_for_review_seconds: float = 0.0
    review_poll_seconds: float = 2.0
    extra: dict[str, Any] = field(default_factory=dict)

    def fields(self) -> dict[str, Any]:
        out: dict[str, Any] = {"data_classification": self.data_classification, **self.extra}
        if self.user_id is not None:
            out["user_id"] = self.user_id
        if self.session_id is not None:
            out["session_id"] = self.session_id
        if self.delegation_chain:
            out["delegation_chain"] = list(self.delegation_chain)
        return out


# ---- pure helpers shared by the async and sync hooks --------------------------------------


def _checked(resp: GuardResponse) -> GuardPayloadIn:
    if resp.decision == Decision.ESCALATE:
        raise GuardrailEscalated(resp)
    if not resp.allowed or resp.payload is None:
        raise GuardrailBlocked(resp)
    return resp.payload


def _after_review(resp: GuardResponse, status: EscalationStatus) -> GuardPayloadIn:
    if status.status == "approved" and status.payload is not None:
        return GuardPayloadIn.model_validate(status.payload)
    if status.status == "pending":
        raise GuardrailEscalated(resp, f"still waiting for human review ({status.escalation_id})")
    raise GuardrailBlocked(resp, status.reason)


def _llm_payload(prompt: str | list[Message] | list[dict[str, str]]) -> GuardPayloadIn:
    if isinstance(prompt, str):
        return GuardPayloadIn(text=prompt)
    return GuardPayloadIn(messages=[m if isinstance(m, Message) else Message.model_validate(m) for m in prompt])


def _llm_result(prompt: Any, safe: GuardPayloadIn) -> Any:
    if isinstance(prompt, str):
        return safe.text
    msgs = safe.messages or []
    if prompt and not isinstance(prompt[0], Message):
        return [m.model_dump() for m in msgs]
    return msgs


def _tool_request(name: str, arguments: dict[str, Any], result: Any = None) -> GuardPayloadIn:
    return GuardPayloadIn(tool_call=ToolCall(name=name, arguments=arguments, result=result))


def _request_kwargs(defaults: GuardDefaults, action: str, resource: str | None) -> dict[str, Any]:
    kw = {"action": action, **defaults.fields()}
    if resource is not None:
        kw["resource"] = resource
    return kw


class GuardHooks:
    def __init__(self, client: GuardClient, defaults: GuardDefaults | None = None, **defaults_kw: Any) -> None:
        self.client = client
        self.defaults = defaults or GuardDefaults(**defaults_kw)

    def with_context(self, **overrides: Any) -> GuardHooks:
        """Same client, different request fields (e.g. per end-user or per session)."""
        return GuardHooks(self.client, dataclasses.replace(self.defaults, **overrides))

    async def _guard(self, stage: Stage, payload: GuardPayloadIn, action: str, resource: str | None = None) -> Any:
        resp = await self.client.guard(stage, payload, **_request_kwargs(self.defaults, action, resource))
        if resp.decision == Decision.ESCALATE and resp.escalation_id and self.defaults.wait_for_review_seconds > 0:
            status = await self.client.wait_for_escalation(
                resp.escalation_id,
                timeout_seconds=self.defaults.wait_for_review_seconds,
                poll_seconds=self.defaults.review_poll_seconds,
            )
            return _after_review(resp, status)
        return _checked(resp)

    async def before_llm(self, prompt: Any, *, action: str | None = None) -> Any:
        """Input stage. `prompt` is a string or a list of messages; returns the same type."""
        safe = await self._guard(Stage.INPUT, _llm_payload(prompt), action or self.defaults.llm_action)
        return _llm_result(prompt, safe)

    async def after_llm(self, text: str, *, action: str | None = None) -> str:
        """Output stage. Returns the text that is safe to show the user."""
        safe = await self._guard(Stage.OUTPUT, GuardPayloadIn(text=text), action or self.defaults.llm_action)
        return safe.text or ""

    async def on_retrieval(
        self, chunks: list[Chunk], *, action: str | None = None, resource: str | None = None
    ) -> list[Chunk]:
        """Retrieval stage. Chunks may come back redacted or be dropped entirely."""
        if not chunks:
            return []
        safe = await self._guard(
            Stage.RETRIEVAL, GuardPayloadIn(chunks=chunks), action or self.defaults.retrieval_action, resource
        )
        return list(safe.chunks or [])

    async def before_tool(self, name: str, arguments: dict[str, Any], *, resource: str | None = None) -> dict[str, Any]:
        """Tool stage before the call: authorization (OPA allowed tools) and argument checks."""
        safe = await self._guard(Stage.TOOL, _tool_request(name, arguments), name, resource)
        return dict(safe.tool_call.arguments) if safe.tool_call else {}

    async def after_tool(
        self, name: str, arguments: dict[str, Any], result: Any, *, resource: str | None = None
    ) -> Any:
        """Tool stage after the call: the result is checked before the agent or LLM sees it."""
        safe = await self._guard(Stage.TOOL, _tool_request(name, arguments, result), name, resource)
        return safe.tool_call.result if safe.tool_call else None


class SyncGuardClient:
    """Blocking twin of `GuardClient` for synchronous agents and tools."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        agent_id: str,
        timeout_seconds: float = 5.0,
        http: httpx.Client | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._agent_id = agent_id
        self._headers = {"X-API-Key": api_key}
        self._own_http = http is None
        self._http = http or httpx.Client(timeout=timeout_seconds)

    def close(self) -> None:
        if self._own_http:
            self._http.close()

    def __enter__(self) -> SyncGuardClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get_escalation(self, escalation_id: str) -> EscalationStatus:
        return _sync_get_escalation(self, escalation_id)

    def guard(self, stage: Stage | str, payload: GuardPayloadIn, *, action: str, **fields: Any) -> GuardResponse:
        stage = Stage(stage)
        body = GuardRequest(agent_id=self._agent_id, action=action, payload=payload, **fields)
        try:
            resp = self._http.post(
                f"{self._base}/v1/guard/{stage.value}",
                json=body.model_dump(mode="json", exclude_none=True),
                headers=self._headers,
            )
        except httpx.HTTPError as exc:
            raise GuardrailGatewayError(None, f"guardrail gateway unreachable: {exc}") from exc
        if resp.status_code in (200, 202, 403):
            try:
                return GuardResponse.model_validate(resp.json())
            except ValueError:
                pass
        raise GuardrailGatewayError(resp.status_code, resp.text[:500])


def _sync_get_escalation(client: SyncGuardClient, escalation_id: str) -> EscalationStatus:
    try:
        resp = client._http.get(f"{client._base}/v1/escalations/{escalation_id}", headers=client._headers)
    except httpx.HTTPError as exc:
        raise GuardrailGatewayError(None, f"guardrail gateway unreachable: {exc}") from exc
    if resp.status_code != 200:
        raise GuardrailGatewayError(resp.status_code, resp.text[:500])
    return EscalationStatus.model_validate(resp.json())


class SyncGuardHooks:
    def __init__(self, client: SyncGuardClient, defaults: GuardDefaults | None = None, **defaults_kw: Any) -> None:
        self.client = client
        self.defaults = defaults or GuardDefaults(**defaults_kw)

    def with_context(self, **overrides: Any) -> SyncGuardHooks:
        return SyncGuardHooks(self.client, dataclasses.replace(self.defaults, **overrides))

    def _guard(self, stage: Stage, payload: GuardPayloadIn, action: str, resource: str | None = None) -> Any:
        resp = self.client.guard(stage, payload, **_request_kwargs(self.defaults, action, resource))
        if resp.decision == Decision.ESCALATE and resp.escalation_id and self.defaults.wait_for_review_seconds > 0:
            deadline = time.monotonic() + self.defaults.wait_for_review_seconds
            while True:
                status = self.client.get_escalation(resp.escalation_id)
                if status.status != "pending" or time.monotonic() >= deadline:
                    return _after_review(resp, status)
                time.sleep(min(self.defaults.review_poll_seconds, max(0.0, deadline - time.monotonic())))
        return _checked(resp)

    def before_llm(self, prompt: Any, *, action: str | None = None) -> Any:
        return _llm_result(prompt, self._guard(Stage.INPUT, _llm_payload(prompt), action or self.defaults.llm_action))

    def after_llm(self, text: str, *, action: str | None = None) -> str:
        return self._guard(Stage.OUTPUT, GuardPayloadIn(text=text), action or self.defaults.llm_action).text or ""

    def on_retrieval(
        self, chunks: list[Chunk], *, action: str | None = None, resource: str | None = None
    ) -> list[Chunk]:
        if not chunks:
            return []
        safe = self._guard(
            Stage.RETRIEVAL, GuardPayloadIn(chunks=chunks), action or self.defaults.retrieval_action, resource
        )
        return list(safe.chunks or [])

    def before_tool(self, name: str, arguments: dict[str, Any], *, resource: str | None = None) -> dict[str, Any]:
        safe = self._guard(Stage.TOOL, _tool_request(name, arguments), name, resource)
        return dict(safe.tool_call.arguments) if safe.tool_call else {}

    def after_tool(self, name: str, arguments: dict[str, Any], result: Any, *, resource: str | None = None) -> Any:
        safe = self._guard(Stage.TOOL, _tool_request(name, arguments, result), name, resource)
        return safe.tool_call.result if safe.tool_call else None
