"""Fast-path latency benchmark (Gate 1: the decision path adds under 15 ms at p99).

    python -m app.bench [--n 5000] [--profile core|content] [--opa-url http://localhost:8181]
                        [--concurrency 1] [--budget-ms 15] [--report bench.json] [--fail-over-budget]

Runs low-risk requests (a chat turn, a knowledge-base search, an internal read-only tool call)
through the real decision path in process: identity binding, the context builder, descriptors,
session state, risk v2, OPA, the guardrail engine, advisors (configured, but they skip low risk),
the decision table and the verification engine. It reports p50/p95/p99 per stage and overall.

What it includes and leaves out, so the number means what Gate 1 means:
- `--profile core` runs only the `noop` guardrail: the platform's own overhead.
  `--profile content` adds the in-process content guardrails (secrets, prompt-injection, enforced).
  Remote guardrails (ai-gateway-pii, content-moderation) are excluded: the gate is the overhead
  *on top of* the content guardrails you already run.
- OPA: with `--opa-url` every request makes the real HTTP call (run `opa run --server --skip-version-check policies/`);
  without it, policy is an in-process allow and the report says so. Measure with OPA for the gate.
- Session state is the in-memory store (Redis adds its own round trip; measure that in staging).
- The audit write is asynchronous in the gateway (a queue), so it isn't on the request path here
  either; only building the audit event is.
- `--concurrency 1` measures the path's own overhead. Higher concurrency on one process measures
  saturation: a replica is one event loop, so past `throughput_rps` requests queue. Use it to size
  replicas, not as the gate number.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import statistics
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

import httpx

from app.advise.factory import build_panel
from app.context.builder import ContextBuilder
from app.context.catalog import ActionRule, AgentInfo, CachedCatalog, TenantCatalog
from app.engine.pipeline import GuardrailEngine
from app.engine.registry import BoundGuardrail, CompiledSnapshot
from app.engine.snapshot import Assignment
from app.gateway.auth import Principal
from app.gateway.flow import run_stage
from app.policy.opa import OpaClient, PolicyDecision
from app.risk.contextual import ContextualDecisions
from app.risk.engine import RiskConfig
from app.session.store import MemorySessionStore
from app.verify.engine import VerificationEngine
from app.verify.store import MemoryVerificationStore
from guardrail_sdk import EnvSecretReader, GuardRequest, Manifest, PluginContext, Stage
from guardrail_sdk.loader import resolve_class

PLUGINS = Path(__file__).resolve().parent / "plugins"
AGENT = "bench-agent"
PRINCIPAL = Principal("k-bench", "bench", "bench", frozenset({"guard:invoke"}), agent_id=AGENT)
GATE_P99_MS = 15.0

# A realistic, low-risk working session.
REQUESTS: list[tuple[Stage, dict[str, Any]]] = [
    (Stage.INPUT, {"action": "llm.chat", "payload": {"text": "Summarise our refund policy in three bullet points."}}),
    (
        Stage.RETRIEVAL,
        {
            "action": "kb.search",
            "payload": {
                "chunks": [
                    {"id": "kb-1", "text": "Refunds are issued to the original payment method within 14 days."},
                    {"id": "kb-2", "text": "Store credit never expires and can be used online or in store."},
                    {"id": "kb-3", "text": "Damaged items are replaced at no cost if reported within 30 days."},
                ]
            },
        },
    ),
    (
        Stage.TOOL,
        {
            "action": "catalog.query",
            "payload": {
                "tool_call": {
                    "name": "catalog.query",
                    "arguments": {
                        "sql": "SELECT id, name, price FROM public.products WHERE category = 'returns' LIMIT 20"
                    },
                }
            },
        },
    ),
    (
        Stage.OUTPUT,
        {"action": "llm.chat", "payload": {"text": "Refunds take up to 14 days; store credit never expires."}},
    ),
]


class AllowPolicy:
    async def evaluate(self, policy_input: dict[str, Any]) -> PolicyDecision:
        return PolicyDecision(True, "allowed (in-process, no OPA)", [])


class Catalog:
    async def load(self, tenant_id: str) -> TenantCatalog:
        return TenantCatalog(
            agents={AGENT: AgentInfo(AGENT, 85, ("*",))},
            actions={
                "llm.chat": [ActionRule("llm.chat", "*", 5)],
                "kb.search": [ActionRule("kb.search", "*", 5)],
                "catalog.query": [ActionRule("catalog.query", "*", 10)],
            },
        )


class NullAudit:
    def submit(self, event: dict[str, Any]) -> None:
        return None


async def _bound(plugin: str, mode: Literal["enforce", "shadow"], order: int, stages: list[str]) -> BoundGuardrail:
    m = Manifest.from_yaml(PLUGINS / plugin / "guardrail.yaml")
    cls = resolve_class(m)
    g = cls(m, PluginContext(http=httpx.AsyncClient(), secrets=EnvSecretReader()))
    await g.setup({})
    a = Assignment(
        id=f"bench-{m.id}",
        guardrail_id=m.id,
        guardrail_version=m.version,
        stages=[Stage(s) for s in stages if s in {x.value for x in m.stages}],
        order=order,
        mode=mode,
    )
    return BoundGuardrail(a, m, g)


async def build(profile: str, policy: Any, advisors_json: str | None) -> SimpleNamespace:
    all_stages = ["input", "retrieval", "tool", "output"]
    bound = [await _bound("noop", "enforce", 1000, all_stages)]
    if profile == "content":
        bound += [
            await _bound("secrets", "enforce", 20, all_stages),
            await _bound("prompt_injection", "enforce", 30, all_stages),
        ]
    snapshot = CompiledSnapshot(version="bench-1", environment="production", bound=bound)
    return SimpleNamespace(
        snapshots=SimpleNamespace(current=snapshot),
        contexts=ContextBuilder(CachedCatalog(Catalog(), ttl_seconds=10**9), "production"),
        policy=policy,
        engine=GuardrailEngine(escalate_as_block=True),
        audit=NullAudit(),
        control_plane=None,
        contextual=ContextualDecisions(
            MemorySessionStore(),
            mode="enforce",
            require_bound_keys=True,
            config=RiskConfig(),
            verifier=VerificationEngine(MemoryVerificationStore()),
            advisors=build_panel(advisors_json),
        ),
    )


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, math.ceil(q * len(s)) - 1))  # nearest rank
    return round(s[k], 3)


def summarise(samples: list[float]) -> dict[str, float]:
    return {
        "n": len(samples),
        "p50_ms": _pct(samples, 0.50),
        "p95_ms": _pct(samples, 0.95),
        "p99_ms": _pct(samples, 0.99),
        "max_ms": round(max(samples), 3) if samples else 0.0,
        "mean_ms": round(statistics.fmean(samples), 3) if samples else 0.0,
    }


async def run(
    *, n: int, profile: str, opa_url: str | None, concurrency: int, budget_ms: float, advisors_json: str | None,
    warmup: int = 200,
) -> dict[str, Any]:  # fmt: skip
    http = httpx.AsyncClient() if opa_url else None
    policy = OpaClient(http, opa_url, "/v1/data/guardrails/authz/decision", 2000) if http and opa_url else AllowPolicy()
    svc = await build(profile, policy, advisors_json)
    per_stage: dict[str, list[float]] = {s.value: [] for s, _ in REQUESTS}
    outcomes: dict[str, int] = {}
    bands: dict[str, int] = {}
    counter = 0
    wall = 0.0

    async def one(i: int, record: bool) -> None:
        nonlocal counter
        stage, body = REQUESTS[i % len(REQUESTS)]
        req = GuardRequest.model_validate({"agent_id": AGENT, "session_id": f"s-{i // 40}", **body})
        counter += 1
        t0 = time.perf_counter()
        res = await run_stage(
            svc,  # type: ignore[arg-type]  # a duck-typed Services, as in the tests
            PRINCIPAL,
            stage,
            req,
            request_id=f"b-{counter}",
            trace_id=f"{counter:032x}",
            started=t0,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        if record:
            per_stage[stage.value].append(elapsed)
            o = res.response.outcome or res.response.decision.value
            outcomes[o] = outcomes.get(o, 0) + 1
            b = res.response.risk.band if res.response.risk else "none"
            bands[b] = bands.get(b, 0) + 1

    try:
        for i in range(warmup):  # builds baselines, imports, caches; not measured
            await one(i, record=False)
        wall = time.perf_counter()
        sem = asyncio.Semaphore(max(1, concurrency))

        async def guarded(i: int) -> None:
            async with sem:
                await one(i, record=True)

        if concurrency <= 1:
            for i in range(n):
                await one(warmup + i, record=True)
        else:
            await asyncio.gather(*(guarded(warmup + i) for i in range(n)))
        wall = time.perf_counter() - wall
    finally:
        if http is not None:
            await http.aclose()
        for b in svc.snapshots.current.bound:
            await b.guardrail.close()
            await b.guardrail.ctx.http.aclose()

    all_samples = [v for vs in per_stage.values() for v in vs]
    overall = summarise(all_samples)
    return {
        "profile": profile,
        "policy": "opa" if opa_url else "in-process allow (no OPA hop: not a gate measurement)",
        "concurrency": concurrency,
        # One process is one event loop on one core: past its throughput, latency is queueing.
        # Size replicas so each stays well below this rate.
        "throughput_rps": round(n / wall, 1) if wall > 0 else None,
        "overall": overall,
        "stages": {k: summarise(v) for k, v in per_stage.items()},
        "outcomes": outcomes,
        "bands": bands,
        "budget_ms": budget_ms,
        "p99_under_budget": overall["p99_ms"] <= budget_ms,
        # The gate verdict only counts with the real policy call in the path.
        "within_budget": (overall["p99_ms"] <= budget_ms) if opa_url else None,
        "python": sys.version.split()[0],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.bench", description=(__doc__ or "").splitlines()[0])
    p.add_argument("--n", type=int, default=5000, help="measured requests (after a warm-up)")
    p.add_argument("--profile", choices=["core", "content"], default="content")
    p.add_argument("--opa-url", default=None, help="e.g. http://localhost:8181 (otherwise in-process allow)")
    p.add_argument("--concurrency", type=int, default=1)
    p.add_argument("--budget-ms", type=float, default=GATE_P99_MS)
    p.add_argument("--advisors", default='[{"name":"local","provider":"local","mode":"enforce"}]',
                   help="ADVISORS_JSON for the run ('' = none); they skip low-risk requests")  # fmt: skip
    p.add_argument("--report", type=Path, default=None)
    p.add_argument("--fail-over-budget", action="store_true", help="exit 1 when p99 is over the budget")
    args = p.parse_args(argv)
    out = asyncio.run(
        run(n=args.n, profile=args.profile, opa_url=args.opa_url, concurrency=args.concurrency,
            budget_ms=args.budget_ms, advisors_json=args.advisors or None)
    )  # fmt: skip
    text = json.dumps(out, indent=2)
    print(text)
    if args.report:
        args.report.write_text(text + "\n", encoding="utf-8")
    if args.fail_over_budget and out["within_budget"] is not True:
        if out["within_budget"] is None:
            print("--fail-over-budget needs --opa-url: without OPA this isn't a gate measurement", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
