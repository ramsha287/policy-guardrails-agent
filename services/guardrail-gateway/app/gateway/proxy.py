"""Proxy mode: an OpenAI-compatible `POST /v1/chat/completions` in front of the LLM provider.

Agents point their OpenAI client at the gateway (base_url=https://gateway/v1, api_key=gk_...) and
get the input and output stages without calling /v1/guard themselves:

  1. input stage   over the request's messages (MODIFY rewrites them, e.g. redacted PII)
  2. the upstream  chat completion, with the gateway's provider key (agents never hold it)
  3. output stage  over each choice's text, and the tool stage over each tool call it asks for

Anything BLOCKed, denied by policy or held for review returns 403 with an OpenAI-style error
body (`type` guardrail_blocked or guardrail_escalated) and nothing from the model. Streaming is
refused (the whole answer has to be checked before any of it is released), as is non-text
content, which the guardrails can't inspect. Both are fail-closed.

Per-request metadata comes from headers: X-Agent-Id (default PROXY_DEFAULT_AGENT_ID),
X-Guardrail-Action (default llm.chat), X-Data-Classification, X-User-Id (or the body's `user`),
X-Session-Id.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx
from pydantic import ValidationError

from app.gateway.auth import Principal
from app.gateway.flow import GuardError, StageResult, run_stage
from guardrail_sdk import Decision, GuardRequest, Stage

if TYPE_CHECKING:
    from app.services import Services

GUARDED_ROLES = {"system": "system", "developer": "system", "user": "user", "assistant": "assistant", "tool": "tool"}


@dataclass(frozen=True)
class ProxyConfig:
    upstream_url: str
    upstream_api_key: str | None = None
    default_agent_id: str = "proxy"
    models: frozenset[str] = frozenset()  # empty = any model


@dataclass
class ProxyResult:
    status: int
    body: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)


def openai_error(status: int, message: str, type_: str, **extra: Any) -> ProxyResult:
    return ProxyResult(status, {"error": {"message": message, "type": type_, "code": type_, "param": None, **extra}})


class ProxyRejected(Exception):
    def __init__(self, result: ProxyResult) -> None:
        super().__init__(result.body["error"]["message"])
        self.result = result


def _text_of(content: Any, where: str) -> str:
    """Message content as text. Only text parts are allowed (the guardrails can't inspect images or audio)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = []
        for part in content:
            if not isinstance(part, dict) or part.get("type") != "text" or not isinstance(part.get("text"), str):
                kind = part.get("type") if isinstance(part, dict) else type(part).__name__
                raise ProxyRejected(
                    openai_error(
                        400,
                        f"{where}: content part of type {kind!r} can't be checked by the guardrails; send text only",
                        "unsupported_content",
                    )
                )
            texts.append(part["text"])
        return "\n".join(texts)
    raise ProxyRejected(openai_error(400, f"{where}: unsupported content", "invalid_request_error"))


def _with_text(content: Any, text: str) -> Any:
    """Put (possibly redacted) text back in the message's original content shape."""
    if isinstance(content, list):
        return [{"type": "text", "text": text}]
    return text


def _meta(headers: Mapping[str, str], body: dict[str, Any], cfg: ProxyConfig) -> dict[str, Any]:
    return {
        "agent_id": headers.get("x-agent-id") or cfg.default_agent_id,
        "action": headers.get("x-guardrail-action") or "llm.chat",
        "data_classification": (headers.get("x-data-classification") or "INTERNAL").upper(),
        "user_id": headers.get("x-user-id") or (body.get("user") if isinstance(body.get("user"), str) else None),
        "session_id": headers.get("x-session-id"),
    }


def _refusal(stage: Stage, result: StageResult) -> ProxyResult | None:
    r = result.response
    if result.status == 202 or r.decision == Decision.ESCALATE:
        return openai_error(
            403,
            f"{stage.value} held for human review: {r.reason}",
            "guardrail_escalated",
            escalation_id=r.escalation_id,
            request_id=r.request_id,
        )
    if r.decision == Decision.BLOCK:
        return openai_error(403, f"{stage.value} blocked: {r.reason}", "guardrail_blocked", request_id=r.request_id)
    return None


class ChatProxy:
    def __init__(self, svc: Services, cfg: ProxyConfig, upstream: httpx.AsyncClient) -> None:
        self.svc = svc
        self.cfg = cfg
        self.upstream = upstream

    async def _stage(
        self, principal: Principal, stage: Stage, meta: dict[str, Any], payload: dict[str, Any], ids: tuple[str, str]
    ) -> StageResult:
        try:
            req = GuardRequest.model_validate({**meta, "payload": payload})
        except ValidationError as exc:
            raise ProxyRejected(openai_error(400, exc.errors()[0]["msg"], "invalid_request_error")) from exc
        try:
            result = await run_stage(self.svc, principal, stage, req, request_id=ids[0], trace_id=ids[1])
        except GuardError as exc:
            raise ProxyRejected(openai_error(exc.status, exc.message, "guardrail_unavailable")) from exc
        refused = _refusal(stage, result)
        if refused is not None:
            raise ProxyRejected(refused)
        return result

    async def chat(
        self, principal: Principal, body: dict[str, Any], headers: Mapping[str, str], *, request_id: str, trace_id: str
    ) -> ProxyResult:
        try:
            return await self._chat(principal, body, headers, (request_id, trace_id))
        except ProxyRejected as rejected:
            rejected.result.headers.setdefault("X-Request-ID", request_id)
            return rejected.result

    async def _chat(
        self, principal: Principal, body: dict[str, Any], headers: Mapping[str, str], ids: tuple[str, str]
    ) -> ProxyResult:
        _refuse_unsupported_request(body)
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ProxyRejected(openai_error(400, "messages must be a non-empty list", "invalid_request_error"))
        if self.cfg.models and body.get("model") not in self.cfg.models:
            raise ProxyRejected(
                openai_error(400, f"model {body.get('model')!r} is not allowed here", "model_not_allowed")
            )
        meta = _meta(headers, body, self.cfg)

        # 1. input stage over every text the provider will see: message contents, plus the arguments
        #    of earlier tool calls in the history and the tool descriptions (both can carry PII or
        #    injected instructions). They go in one stage call, so one decision and one audit event.
        guarded: list[dict[str, str]] = []
        for i, m in enumerate(messages):
            if not isinstance(m, dict) or m.get("role") not in GUARDED_ROLES:
                raise ProxyRejected(openai_error(400, f"messages[{i}]: unsupported role", "invalid_request_error"))
            guarded.append({"role": GUARDED_ROLES[m["role"]], "content": _text_of(m.get("content"), f"messages[{i}]")})
        extras = _request_extras(body)
        guarded.extend({"role": role, "content": text} for _, role, text in extras)
        inp = await self._stage(principal, Stage.INPUT, meta, {"messages": guarded}, ids)
        forward = json.loads(json.dumps(body))  # deep copy; only redacted texts change
        redacted = inp.response.payload.messages if inp.response.payload is not None else None
        if redacted is not None:
            for i, (orig, new) in enumerate(zip(messages, redacted, strict=False)):
                if orig.get("content") is not None:
                    forward["messages"][i]["content"] = _with_text(orig.get("content"), new.content)
            for (setter, _, _), new in zip(extras, redacted[len(messages) :], strict=False):
                setter(forward, new.content)

        # 2. upstream
        headers_out = {"Content-Type": "application/json"}
        if self.cfg.upstream_api_key:
            headers_out["Authorization"] = f"Bearer {self.cfg.upstream_api_key}"
        try:
            resp = await self.upstream.post(
                f"{self.cfg.upstream_url.rstrip('/')}/chat/completions", json=forward, headers=headers_out
            )
        except httpx.HTTPError as exc:
            raise ProxyRejected(
                openai_error(502, f"LLM provider unreachable ({exc.__class__.__name__})", "upstream_unavailable")
            ) from exc
        try:
            data = resp.json()
        except ValueError as exc:
            raise ProxyRejected(
                openai_error(502, f"LLM provider returned HTTP {resp.status_code} without JSON", "upstream_error")
            ) from exc
        if resp.status_code >= 400:  # the provider's own error, passed through (no model output to check)
            return ProxyResult(resp.status_code, data if isinstance(data, dict) else {"error": data})

        # 3. rebuild the response from an allowlist (nothing unchecked slips through: logprobs,
        #    audio, legacy function_call, custom tool calls), then check every text and tool call.
        out_body = _sanitize_response(data)
        decisions = {"input": inp.response.decision.value}
        for choice in out_body["choices"]:
            msg = choice["message"]
            for part in ("content", "refusal"):
                text = msg.get(part)
                if isinstance(text, str) and text:
                    out = await self._stage(principal, Stage.OUTPUT, meta, {"text": text}, ids)
                    decisions["output"] = _strongest(decisions.get("output"), out.response.decision.value)
                    if out.response.payload is not None and out.response.payload.text is not None:
                        msg[part] = out.response.payload.text
            for ti, call in enumerate(msg.get("tool_calls") or []):
                fn = call["function"]
                try:
                    args = json.loads(fn["arguments"])
                except ValueError:
                    args = None
                if not isinstance(args, dict):
                    raise ProxyRejected(
                        openai_error(
                            403,
                            f"choices[{choice['index']}].tool_calls[{ti}]: arguments are not a JSON object",
                            "guardrail_blocked",
                        )
                    )
                tool_meta = {**meta, "action": fn["name"] or "unknown"}  # same as the SDK's before_tool
                t = await self._stage(
                    principal, Stage.TOOL, tool_meta, {"tool_call": {"name": fn["name"], "arguments": args}}, ids
                )
                decisions["tool"] = _strongest(decisions.get("tool"), t.response.decision.value)
                tc = t.response.payload.tool_call if t.response.payload is not None else None
                if tc is not None:
                    fn["arguments"] = json.dumps(tc.arguments, separators=(",", ":"))
        return ProxyResult(
            200,
            out_body,
            {f"X-Guardrail-{k.title()}-Decision": v for k, v in decisions.items()} | {"X-Request-ID": ids[0]},
        )


# Request features whose content the guardrails can't check, or whose output bypasses them.
UNSUPPORTED_REQUEST = {
    "logprobs": "logprobs would return the raw model tokens next to the checked text",
    "top_logprobs": "logprobs would return the raw model tokens next to the checked text",
    "audio": "audio output can't be checked",
    "functions": "legacy functions are not supported; use tools",
    "function_call": "legacy function_call is not supported; use tool_choice",
    "prediction": "predicted outputs are not supported",
}


def _refuse_unsupported_request(body: dict[str, Any]) -> None:
    if body.get("stream"):
        raise ProxyRejected(
            openai_error(400, "stream=true is not supported through the guardrail proxy", "unsupported_stream")
        )
    for key, why in UNSUPPORTED_REQUEST.items():
        if body.get(key):
            raise ProxyRejected(openai_error(400, f"{key}: {why}", "unsupported_parameter"))
    modalities = body.get("modalities")
    if modalities is not None and modalities != ["text"]:
        raise ProxyRejected(
            openai_error(400, "only text output can be checked (modalities=['text'])", "unsupported_parameter")
        )
    for i, tool in enumerate(body.get("tools") or []):
        if not isinstance(tool, dict) or tool.get("type") != "function" or not isinstance(tool.get("function"), dict):
            raise ProxyRejected(
                openai_error(400, f"tools[{i}]: only function tools are supported", "unsupported_parameter")
            )


def _request_extras(body: dict[str, Any]) -> list[tuple[Any, str, str]]:
    """Texts besides message content that reach the provider: (setter, role for the stage, text)."""
    extras: list[tuple[Any, str, str]] = []
    for i, m in enumerate(body.get("messages") or []):
        for j, call in enumerate(m.get("tool_calls") or [] if isinstance(m, dict) else []):
            fn = call.get("function") if isinstance(call, dict) else None
            if isinstance(fn, dict) and isinstance(fn.get("arguments"), str) and fn["arguments"]:

                def set_args(doc: dict[str, Any], text: str, i: int = i, j: int = j) -> None:
                    doc["messages"][i]["tool_calls"][j]["function"]["arguments"] = text

                extras.append((set_args, "assistant", fn["arguments"]))
    for k, tool in enumerate(body.get("tools") or []):
        desc = tool["function"].get("description")
        if isinstance(desc, str) and desc:

            def set_desc(doc: dict[str, Any], text: str, k: int = k) -> None:
                doc["tools"][k]["function"]["description"] = text

            extras.append((set_desc, "system", desc))
    return extras


def _bad_upstream(why: str) -> ProxyRejected:
    return ProxyRejected(openai_error(502, f"LLM provider response not understood: {why}", "upstream_error"))


def _unchecked(where: str) -> ProxyRejected:
    return ProxyRejected(
        openai_error(403, f"{where} can't be checked by the guardrails; withheld", "guardrail_blocked")
    )


def _sanitize_response(data: Any) -> dict[str, Any]:
    """Keep only fields the proxy checks or that carry no model output (ids, usage)."""
    if not isinstance(data, dict) or not isinstance(data.get("choices"), list):
        raise _bad_upstream("no choices")
    out: dict[str, Any] = {
        k: data[k]
        for k in ("id", "object", "created", "model", "system_fingerprint", "service_tier", "usage")
        if k in data
    }
    choices = []
    for ci, ch in enumerate(data["choices"]):
        if not isinstance(ch, dict) or not isinstance(ch.get("message"), dict):
            raise _bad_upstream(f"choices[{ci}] has no message")
        msg = ch["message"]
        for key in ("audio", "function_call"):
            if msg.get(key):
                raise _unchecked(f"choices[{ci}].message.{key}")
        clean: dict[str, Any] = {"role": msg.get("role") or "assistant"}
        for key in ("content", "refusal"):
            value = msg.get(key)
            if value is not None and not isinstance(value, str):
                raise _unchecked(f"choices[{ci}].message.{key} (not text)")
            clean[key] = value
        calls = []
        for ti, call in enumerate(msg.get("tool_calls") or []):
            fn = call.get("function") if isinstance(call, dict) else None
            if not isinstance(call, dict) or call.get("type", "function") != "function" or not isinstance(fn, dict):
                raise _unchecked(f"choices[{ci}].tool_calls[{ti}] (not a function call)")
            args = fn.get("arguments") or "{}"
            calls.append(
                {
                    "id": call.get("id"),
                    "type": "function",
                    "function": {"name": str(fn.get("name") or ""), "arguments": args if isinstance(args, str) else ""},
                }
            )
        if calls:
            clean["tool_calls"] = calls
        choices.append({"index": ch.get("index", ci), "message": clean, "finish_reason": ch.get("finish_reason")})
    out["choices"] = choices
    return out


_ORDER = {"allow": 0, "modify": 1, "escalate": 2, "block": 3}


def _strongest(a: str | None, b: str) -> str:
    return b if a is None or _ORDER.get(b, 0) > _ORDER.get(a, 0) else a
