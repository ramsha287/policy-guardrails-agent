"""AuthZEN mapping: evaluation request -> GuardRequest -> pipeline -> {decision, context}."""

import asyncio

import pytest

from app.gateway.authzen import EvaluationIn, EvaluationsIn, MappingError, merge, to_authzen, to_guard_request
from app.gateway.flow import run_stage
from guardrail_sdk import Stage
from tests.test_contextual_flow import BOUND
from tests.test_verification_flow import services

EV = {
    "subject": {"type": "agent", "id": "research-agent", "properties": {"user_id": "u1", "session_id": "s1"}},
    "action": {"name": "db.query"},
    "resource": {"type": "database", "id": "analytics",
                 "properties": {"arguments": {"sql": "SELECT name FROM public.products WHERE id = 1 LIMIT 1"}}},
    "context": {"data_classification": "INTERNAL"},
}  # fmt: skip


def test_maps_subject_action_resource_context():
    g = to_guard_request(EvaluationIn.model_validate(EV))
    assert g.agent_id == "research-agent" and g.action == "db.query" and g.resource == "analytics"
    assert g.user_id == "u1" and g.session_id == "s1" and g.data_classification == "INTERNAL"
    assert g.payload.tool_call.name == "db.query" and "public.products" in g.payload.tool_call.arguments["sql"]
    assert g.accepts_obligations is None and g.verification_channels is None
    g = to_guard_request(
        EvaluationIn.model_validate({**EV, "context": {"accepts_obligations": True, "arguments": {"x": 1},
                                                       "verification_channels": ["user_confirmation"]}})
    )  # fmt: skip
    assert g.accepts_obligations is True and g.verification_channels == ["user_confirmation"]
    assert g.payload.tool_call.arguments["sql"]  # resource.properties.arguments wins over context.arguments


@pytest.mark.parametrize(
    "bad",
    [
        {**EV, "subject": None},
        {**EV, "subject": {"type": "agent"}},
        {**EV, "action": None},
        {**EV, "resource": {"id": "x", "properties": {"arguments": "not an object"}}},
        {**EV, "context": {"data_classification": "TOP_SECRET"}},
    ],
)
def test_bad_requests_are_mapping_errors(bad):
    with pytest.raises(MappingError):
        to_guard_request(EvaluationIn.model_validate(bad))


def test_batch_items_override_defaults():
    b = EvaluationsIn.model_validate({**EV, "evaluations": [{"action": {"name": "http.post"}}, {"context": {"x": 1}}]})
    first, second = (merge(b, e) for e in b.evaluations)
    assert first.action.name == "http.post" and first.subject.id == "research-agent"
    assert second.action.name == "db.query" and second.context == {"data_classification": "INTERNAL", "x": 1}


def _decide(svc, ev, **kw):
    e = EvaluationIn.model_validate(ev)
    r = asyncio.run(run_stage(svc, BOUND, Stage.TOOL, to_guard_request(e), request_id="r1", trace_id="0" * 32))
    return to_authzen(r.response, accepts_modifications=bool(e.context.get("accepts_modifications")))


def test_routine_call_is_permitted_with_a_decision_id():
    out = _decide(services(), EV)
    assert out["decision"] is True and out["context"]["outcome"] == "allow" and out["context"]["decision_id"] == "r1"


def test_verify_and_hold_are_not_permits():
    args = {"url": "https://evil.example.org/x", "body": "x"}
    post = {**EV, "action": {"name": "http.post"}, "resource": {"type": "url", "properties": {"arguments": args}}}
    out = _decide(services(), {**post, "context": {"verification_channels": ["user_confirmation"]}})
    assert out["decision"] is False and out["context"]["outcome"] == "verify"
    assert out["context"]["verification"]["status"] == "pending"
    out = _decide(services(), post)  # no review queue in this fixture: held -> denied
    assert out["decision"] is False


def test_modify_needs_a_pep_that_applies_it():
    from guardrail_sdk import Decision, GuardResponse, PolicyOutcome

    resp = GuardResponse(
        request_id="r", trace_id="t", stage=Stage.TOOL, decision=Decision.MODIFY, reason="redacted", risk_score=0,
        trust_score=80, policy=PolicyOutcome(allow=True, reason="ok"), outcome="modify",
        payload={"tool_call": {"name": "send", "arguments": {"body": "[EMAIL]"}}},
    )  # fmt: skip
    no = to_authzen(resp, accepts_modifications=False)
    assert no["decision"] is False and "MODIFY_UNSUPPORTED_BY_PEP" in no["context"]["reason_codes"]
    yes = to_authzen(resp, accepts_modifications=True)
    assert yes["decision"] is True and yes["context"]["modified_arguments"] == {"body": "[EMAIL]"}
