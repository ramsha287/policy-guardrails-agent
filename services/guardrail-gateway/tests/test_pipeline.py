from app.engine.pipeline import GuardrailEngine
from guardrail_sdk import Decision, GuardrailResult, Payload, Stage
from tests.helpers import bind, make_ctx, modify_text, result, snapshot

ENGINE = GuardrailEngine(default_timeout_ms=200)
P = Payload(stage="input", text="hello jane@example.com")


async def run(snap, payload=P, stage=Stage.INPUT, obligations=None, **ctx):
    return await ENGINE.run(snap, stage, make_ctx(**ctx), payload, obligations)


async def test_no_guardrails_allows():
    out = await run(snapshot())
    assert out.decision == Decision.ALLOW and out.payload == P
    assert "no guardrails" in out.reason


async def test_modify_chains_to_next_guardrail():
    first = bind("redact", modify_text(lambda t: t.replace("jane@example.com", "[EMAIL]")), order=1)
    second = bind("upper", modify_text(str.upper), order=2)
    out = await run(snapshot(second, first))  # order field decides, not list order
    assert out.decision == Decision.MODIFY
    assert out.payload.text == "HELLO [EMAIL]"
    assert second.guardrail.seen[0].text == "hello [EMAIL]"


async def test_block_short_circuits():
    blocker = bind("blocker", result("block", "nope", 90), order=1)
    later = bind("later", order=2)
    out = await run(snapshot(blocker, later))
    assert out.decision == Decision.BLOCK and out.payload is None
    assert out.reason == "blocker: nope" and out.risk_score == 90
    assert later.guardrail.seen == []


async def test_strongest_wins_and_shadow_is_ignored():
    shadow_block = bind("shadow-block", result("block"), order=1, mode="shadow")
    modifier = bind("mod", modify_text(lambda t: t + "!"), order=2)
    out = await run(snapshot(shadow_block, modifier))
    assert out.decision == Decision.MODIFY
    assert [r.mode for r in out.results] == ["shadow", "enforce"]


async def test_shadow_modify_does_not_change_payload():
    out = await run(snapshot(bind("m", modify_text(str.upper), mode="shadow")))
    assert out.decision == Decision.ALLOW and out.payload.text == P.text


async def test_fail_closed_on_error():
    def boom(c, p):
        raise RuntimeError("down")

    out = await run(snapshot(bind("flaky", boom, failure_mode="fail_closed")))
    assert out.decision == Decision.BLOCK
    assert out.results[0].error == "RuntimeError" and "fail_closed" in out.reason


async def test_fail_open_on_error():
    def boom(c, p):
        raise RuntimeError("down")

    out = await run(snapshot(bind("flaky", boom, failure_mode="fail_open")))
    assert out.decision == Decision.ALLOW and out.results[0].error == "RuntimeError"


async def test_timeout_uses_failure_mode():
    out = await run(snapshot(bind("slow", delay=0.5, timeout_ms=50, failure_mode="fail_closed")))
    assert out.decision == Decision.BLOCK and out.results[0].error == "timeout"


async def test_undeclared_decision_is_an_error():
    out = await run(snapshot(bind("liar", result("block"), decisions=("allow",), failure_mode="fail_closed")))
    assert out.results[0].error == "undeclared decision block"
    assert out.decision == Decision.BLOCK


async def test_modify_that_changes_shape_is_rejected():
    def reshape(c, p):
        return GuardrailResult(
            decision=Decision.MODIFY,
            reason="x",
            modified_payload=Payload(stage="input", messages=[{"role": "user", "content": "x"}]),
        )

    out = await run(snapshot(bind("reshaper", reshape, failure_mode="fail_closed")))
    assert out.results[0].error == "MODIFY changed the payload shape"
    assert out.decision == Decision.BLOCK


async def test_escalate_becomes_block_until_review_queue():
    out = await run(snapshot(bind("esc", result("escalate", "needs human"))))
    assert out.decision == Decision.BLOCK and "escalation required" in out.reason


async def test_missing_obligation_blocks():
    out = await run(snapshot(bind("other")), obligations=["ai-gateway-pii"])
    assert out.decision == Decision.BLOCK and "ai-gateway-pii" in out.reason


async def test_obligation_not_satisfied_by_shadow():
    out = await run(snapshot(bind("ai-gateway-pii", mode="shadow")), obligations=["ai-gateway-pii"])
    assert out.decision == Decision.BLOCK


async def test_obligation_satisfied():
    out = await run(snapshot(bind("ai-gateway-pii")), obligations=["ai-gateway-pii"])
    assert out.decision == Decision.ALLOW


async def test_scope_resolution_most_specific_wins():
    g = bind("pii", result("block"), scope_type="global")
    tenant_off = bind("pii", scope_type="tenant", scope_id="demo", enabled=False)
    agent_on = bind("pii", modify_text(str.upper), scope_type="agent", scope_id="demo/vip")
    snap = snapshot(g, tenant_off, agent_on)
    assert (await run(snap, tenant_id="other")).decision == Decision.BLOCK  # global applies
    assert (await run(snap, tenant_id="demo")).decision == Decision.ALLOW  # tenant disabled it
    assert (await run(snap, tenant_id="demo", agent_id="vip")).decision == Decision.MODIFY  # agent override


async def test_stage_filtering():
    snap = snapshot(bind("out-only", result("block"), stages=("output",)))
    assert (await run(snap)).decision == Decision.ALLOW


async def test_parallel_group_runs_concurrently():
    import time

    a = bind("pa", delay=0.1, parallel_group="g1", decisions=("allow",), capabilities={"parallel_safe": True})
    b = bind("pb", delay=0.1, parallel_group="g1", decisions=("allow",), capabilities={"parallel_safe": True})
    t0 = time.perf_counter()
    out = await run(snapshot(a, b))
    assert time.perf_counter() - t0 < 0.18
    assert len(out.results) == 2 and out.decision == Decision.ALLOW
