"""The guard flow with contextual decisions (identity binding, descriptors, sessions, risk v2).

These call run_stage directly, so they cover the same code as POST /v1/guard/{stage} and the proxy.
"""

import asyncio
import json
from types import SimpleNamespace

from app.context.builder import ContextBuilder
from app.context.catalog import ActionRule, AgentInfo, CachedCatalog, TenantCatalog
from app.engine.pipeline import GuardrailEngine
from app.gateway.auth import Principal
from app.gateway.flow import GuardError, run_stage
from app.policy.opa import PolicyDecision
from app.risk.contextual import ContextualDecisions
from app.session.store import MemorySessionStore
from guardrail_sdk import Decision, GuardRequest, Stage
from tests.helpers import bind, snapshot

UNBOUND = Principal("k0", "demo", "legacy", frozenset({"guard:invoke"}))
BOUND = Principal("k1", "demo", "research", frozenset({"guard:invoke"}), agent_id="research-agent")


class Catalog:
    async def load(self, tenant_id):
        return TenantCatalog(
            agents={"research-agent": AgentInfo("research-agent", 80, ("*",))},
            actions={
                "llm.chat": [ActionRule("llm.chat", "*", 10)],
                "kb.search": [ActionRule("kb.search", "*", 10)],
                "db.query": [ActionRule("db.query", "*", 40)],
                "catalog.query": [ActionRule("catalog.query", "*", 20)],
                "http.post": [ActionRule("http.post", "*", 30)],
            },
        )


class Policy:
    def __init__(self, allow=True):
        self.allow = allow
        self.inputs = []

    async def evaluate(self, policy_input):
        self.inputs.append(policy_input)
        return PolicyDecision(self.allow, "allowed" if self.allow else "nope", [])


class Audit:
    def __init__(self):
        self.events = []

    def submit(self, e):
        self.events.append(e)


class ControlPlane:
    def __init__(self):
        self.reviews = []

    async def create_review(self, body):
        self.reviews.append(body)
        return {"escalation_id": f"esc-{len(self.reviews)}"}


def services(mode="shadow", *, require_bound=False, policy=None, control_plane=None):
    allow_all = bind("noop", stages=("input", "retrieval", "tool", "output"))
    snap = snapshot(allow_all)
    return SimpleNamespace(
        snapshots=SimpleNamespace(current=snap),
        contexts=ContextBuilder(CachedCatalog(Catalog()), "production"),
        policy=policy or Policy(),
        engine=GuardrailEngine(escalate_as_block=control_plane is None),
        audit=Audit(),
        control_plane=control_plane,
        contextual=ContextualDecisions(MemorySessionStore(), mode=mode, require_bound_keys=require_bound),
    )


def req(stage, **kw):
    base = {"agent_id": "research-agent", "action": "llm.chat", "session_id": "s1", "payload": {"text": "hi"}}
    base.update(kw)
    return GuardRequest.model_validate(base)


EXPORT = {
    "action": "db.query",
    "data_classification": "PII",
    "payload": {
        "tool_call": {
            "name": "db.query",
            "arguments": {"sql": "SELECT email, phone FROM public.customers ORDER BY id DESC LIMIT 10000"},
        }
    },
}
RETRIEVE = {"action": "kb.search", "payload": {"chunks": [{"id": "c1", "text": "ticket from outside"}]}}


def call(svc, stage, body, principal=BOUND):
    return asyncio.run(run_stage(svc, principal, stage, body, request_id="r", trace_id="0" * 32))


async def acall(svc, stage, body, principal=BOUND):
    return await run_stage(svc, principal, stage, body, request_id="r", trace_id="0" * 32)


def test_bound_key_cannot_act_as_another_agent():
    svc = services()
    res = call(svc, Stage.INPUT, req("input", agent_id="admin-agent"))
    assert res.status == 403 and res.response.decision == Decision.BLOCK
    assert res.response.outcome == "deny" and res.response.reason_codes == ["KEY_AGENT_MISMATCH"]
    assert svc.policy.inputs == []  # nothing else ran
    ev = svc.audit.events[0]
    assert ev["outcome"] == "deny" and ev["reason_codes"] == ["KEY_AGENT_MISMATCH"] and ev["assurance"] == "A1"


def test_unbound_keys_can_be_refused():
    res = call(services(require_bound=True), Stage.INPUT, req("input"), principal=UNBOUND)
    assert res.status == 403 and res.response.reason_codes == ["UNBOUND_KEY"]
    res = call(services(), Stage.INPUT, req("input"), principal=UNBOUND)
    assert res.status == 200 and res.response.assurance == "A0"


def test_shadow_mode_computes_and_records_but_does_not_change_the_decision():
    svc = services("shadow")

    async def go():
        await acall(svc, Stage.RETRIEVAL, req("retrieval", **RETRIEVE))
        return await acall(svc, Stage.TOOL, req("tool", **EXPORT))

    res = asyncio.run(go())
    r = res.response
    assert res.status == 200 and r.decision == Decision.ALLOW and r.outcome == "allow"
    assert r.risk is not None and r.risk.mode == "shadow" and r.risk.band == "critical"
    assert r.risk.would_outcome == "hold"
    assert {"TAINTED_SESSION", "NEW_RESOURCE", "VOLUME_NO_BASELINE"} <= set(r.reason_codes)
    ev = svc.audit.events[-1]
    assert ev["descriptor"]["tables"] == ["public.customers"] and ev["descriptor"]["rows_requested"] == 10000
    assert ev["risk"]["would_outcome"] == "hold" and ev["outcome"] == "allow"


def test_enforce_holds_high_risk_requests_for_review():
    cp = ControlPlane()
    svc = services("enforce", control_plane=cp)
    res = call(svc, Stage.TOOL, req("tool", **EXPORT))
    assert res.status == 202 and res.response.decision == Decision.ESCALATE and res.response.escalation_id == "esc-1"
    # high risk asks for verification; until verifiers exist that means a human hold
    assert res.response.outcome == "hold" and {"RISK_HIGH", "VERIFY_AS_HOLD"} <= set(res.response.reason_codes)
    assert cp.reviews[0]["guardrail_id"] == "gateway-risk"
    assert cp.reviews[0]["reason"].startswith("held for review: risk high")


def test_enforce_without_review_queue_blocks():
    res = call(services("enforce"), Stage.TOOL, req("tool", **EXPORT))
    assert res.status == 403 and res.response.decision == Decision.BLOCK and res.response.payload is None
    assert res.response.outcome == "deny"


def test_enforce_allows_routine_requests_unchanged():
    svc = services("enforce")
    res = call(svc, Stage.INPUT, req("input"))
    assert res.status == 200 and res.response.outcome == "allow" and res.response.payload.text == "hi"


def test_row_limit_obligation_only_for_callers_that_apply_it():
    q = {
        "action": "catalog.query",
        "payload": {"tool_call": {"name": "catalog.query", "arguments": {"sql": "select id, name from products"}}},
    }
    with_ob = call(services("enforce"), Stage.TOOL, req("tool", accepts_obligations=True, **q))
    r = with_ob.response
    assert with_ob.status == 200 and r.decision == Decision.ALLOW
    assert r.outcome == "allow_restricted" and r.obligations == {"row_limit": 1000}
    without = call(services("enforce"), Stage.TOOL, req("tool", **q))
    assert without.response.decision == Decision.BLOCK and "OBLIGATIONS_UNSUPPORTED" in without.response.reason_codes


def test_repeated_denials_quarantine_the_session_in_enforce_mode():
    policy = Policy(allow=False)
    svc = services("enforce", policy=policy)

    async def go():
        for _ in range(5):
            await acall(svc, Stage.INPUT, req("input"))
        policy.allow = True
        return await acall(svc, Stage.INPUT, req("input"))

    res = asyncio.run(go())
    assert res.response.decision == Decision.BLOCK and res.response.outcome == "quarantine_session"
    # the trust penalty after 3 denials shows up as lower trust
    assert res.response.risk.trust < 80
    other = call(svc, Stage.INPUT, req("input", session_id="s2"))
    assert other.response.decision == Decision.ALLOW  # a fresh session is not quarantined


def test_policy_input_carries_context_but_never_payload_text():
    svc = services("shadow")
    call(svc, Stage.TOOL, req("tool", **EXPORT))
    pi = svc.policy.inputs[0]
    assert pi["identity"] == {"assurance": "A1", "key_agent_id": "research-agent"}
    assert pi["descriptor"]["verb"] == "read" and pi["risk_v2"]["band"] in ("high", "critical")
    assert "session" in pi
    dumped = json.dumps(pi)
    assert "SELECT email" not in dumped and "ORDER BY" not in dumped


def test_off_mode_still_describes_but_skips_session_and_risk():
    svc = services("off")
    res = call(svc, Stage.TOOL, req("tool", **EXPORT))
    assert res.response.risk is None and svc.audit.events[0]["descriptor"]["kind"] == "sql"


def test_no_snapshot_is_still_503():
    svc = services()
    svc.snapshots.current = None
    try:
        call(svc, Stage.INPUT, req("input"))
    except GuardError as exc:
        assert exc.status == 503
    else:
        raise AssertionError("expected GuardError")


def test_new_session_ids_do_not_escape_an_agent_quarantine():
    policy = Policy(allow=False)
    svc = services("enforce", policy=policy)

    async def go():
        for i in range(10):
            await acall(svc, Stage.INPUT, req("input", session_id=f"s{i}"))
        policy.allow = True
        fresh = await acall(svc, Stage.INPUT, req("input", session_id="brand-new"))
        none = await acall(svc, Stage.INPUT, req("input", session_id=None))
        return fresh, none

    fresh, none = asyncio.run(go())
    assert fresh.response.outcome == "quarantine_session" and none.response.outcome == "quarantine_session"
