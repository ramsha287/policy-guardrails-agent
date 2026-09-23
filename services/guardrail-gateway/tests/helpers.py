"""Test doubles shared by the gateway tests."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from app.engine.registry import BoundGuardrail, CompiledSnapshot
from app.engine.snapshot import Assignment
from guardrail_sdk import (
    Decision,
    EnvSecretReader,
    Guardrail,
    GuardrailResult,
    Manifest,
    Payload,
    PluginContext,
    SecurityContext,
)


def make_ctx(**over: Any) -> SecurityContext:
    base = dict(
        request_id="req-1",
        trace_id="a" * 32,
        tenant_id="demo",
        agent_id="research-agent",
        user_id="u1",
        action="llm.chat",
        trust_score=80,
        risk_score=10,
        data_classification="INTERNAL",
        environment="dev",
    )
    base.update(over)
    return SecurityContext(**base)


def manifest(gid: str, decisions=("allow", "modify", "block", "escalate"), **over: Any) -> Manifest:
    base = dict(
        id=gid,
        version="1.0.0",
        kind="local",
        stages=["input", "retrieval", "tool", "output"],
        description="d",
        owner="o",
        data_handling="none",
        decisions_emitted=list(decisions),
        entrypoint="tests.helpers:Scripted",
        capabilities={"emits_modify": "modify" in decisions},
    )
    base.update(over)
    return Manifest.model_validate(base)


class Scripted(Guardrail):
    """Returns whatever `behaviour` says. behaviour(ctx, payload) -> GuardrailResult or raises."""

    def __init__(self, m: Manifest, ctx: PluginContext, behaviour=None, delay: float = 0.0) -> None:
        super().__init__(m, ctx)
        self.behaviour = behaviour or (lambda c, p: GuardrailResult(decision=Decision.ALLOW, reason="ok"))
        self.delay = delay
        self.seen: list[Payload] = []

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        self.seen.append(payload)
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.behaviour(context, payload)


def plugin_ctx() -> PluginContext:
    return PluginContext(http=httpx.AsyncClient(), secrets=EnvSecretReader())


def bind(
    gid: str,
    behaviour=None,
    *,
    order: int = 10,
    mode: str = "enforce",
    scope_type: str = "global",
    scope_id: str | None = None,
    stages=("input",),
    failure_mode: str | None = None,
    timeout_ms: int | None = None,
    parallel_group: str | None = None,
    enabled: bool = True,
    delay: float = 0.0,
    **manifest_over: Any,
) -> BoundGuardrail:
    m = manifest(gid, **manifest_over)
    a = Assignment(
        id=f"a-{gid}-{scope_type}-{scope_id}",
        guardrail_id=gid,
        guardrail_version="1.0.0",
        scope_type=scope_type,
        scope_id=scope_id,
        stages=list(stages),
        order=order,
        mode=mode,
        failure_mode=failure_mode,
        timeout_ms=timeout_ms,
        parallel_group=parallel_group,
        enabled=enabled,
    )
    return BoundGuardrail(a, m, Scripted(m, plugin_ctx(), behaviour, delay))


def snapshot(*bound: BoundGuardrail) -> CompiledSnapshot:
    return CompiledSnapshot(version="test-1", environment="dev", bound=list(bound))


def modify_text(fn):
    def behaviour(ctx, p: Payload) -> GuardrailResult:
        return GuardrailResult(
            decision=Decision.MODIFY,
            reason="modified",
            risk_score=30,
            modified_payload=p.model_copy(update={"text": fn(p.text)}),
        )

    return behaviour


def result(decision: str, reason: str = "r", risk: int = 0):
    return lambda c, p: GuardrailResult(decision=Decision(decision), reason=reason, risk_score=risk)


class MockHttp:
    """Minimal HTTP router over httpx.MockTransport (no extra test dependencies)."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Any] = {}
        self.calls: list[httpx.Request] = []

    def on(self, method: str, url: str, handler: Any) -> None:
        """`handler` is an httpx.Response or a callable(request) -> httpx.Response."""
        self.routes[(method.upper(), url)] = handler

    def _dispatch(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        key = (request.method, str(request.url.copy_with(query=None)))
        handler = self.routes.get(key)
        if handler is None:
            return httpx.Response(599, json={"error": f"no mock for {key}"})
        return handler(request) if callable(handler) else handler

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._dispatch))
