import pytest
from pydantic import ValidationError

from guardrail_sdk import Chunk, Decision, GuardrailResult, Message, Payload, SecurityContext, strongest
from guardrail_sdk.manifest import Manifest, sdk_version_satisfies


def test_strongest_precedence():
    assert strongest([]) == Decision.ALLOW
    assert strongest([Decision.ALLOW, Decision.MODIFY]) == Decision.MODIFY
    assert strongest([Decision.MODIFY, Decision.ESCALATE]) == Decision.ESCALATE
    assert strongest([Decision.ESCALATE, Decision.BLOCK, Decision.ALLOW]) == Decision.BLOCK


def test_modify_requires_payload_and_reason():
    with pytest.raises(ValidationError):
        GuardrailResult(decision=Decision.MODIFY, reason="x")
    with pytest.raises(ValidationError):
        GuardrailResult(decision=Decision.ALLOW, reason="   ")


@pytest.mark.parametrize(
    "stage,fields",
    [("input", {}), ("output", {}), ("retrieval", {"text": "x"}), ("tool", {"text": "x"})],
)
def test_payload_requires_stage_content(stage, fields):
    with pytest.raises(ValidationError):
        Payload(stage=stage, **fields)


def test_context_is_frozen():
    ctx = SecurityContext(
        request_id="r",
        trace_id="t" * 32,
        tenant_id="t",
        agent_id="a",
        action="llm.chat",
        trust_score=50,
        risk_score=10,
        environment="dev",
    )
    with pytest.raises(ValidationError):
        ctx.trust_score = 100  # type: ignore[misc]


def test_same_shape():
    orig = Payload(stage="retrieval", chunks=[Chunk(id="a", text="1"), Chunk(id="b", text="2")])
    assert orig.same_shape_as(Payload(stage="retrieval", chunks=[Chunk(id="a", text="x")]))  # dropping is fine
    assert not orig.same_shape_as(Payload(stage="retrieval", chunks=[Chunk(id="z", text="x")]))  # inventing is not
    msgs = Payload(stage="input", messages=[Message(role="user", content="hi")])
    assert not msgs.same_shape_as(Payload(stage="input", messages=[Message(role="system", content="hi")]))
    assert not msgs.same_shape_as(Payload(stage="input", text="hi"))


def test_version_ranges():
    assert sdk_version_satisfies("1.0.0", ">=1.0,<2.0")
    assert not sdk_version_satisfies("2.0.0", ">=1.0,<2.0")
    assert sdk_version_satisfies("1.4.2", "==1.4.2")


def _manifest(**over):
    base = dict(
        id="demo-guard",
        version="1.0.0",
        kind="local",
        stages=["input"],
        description="d",
        owner="o",
        data_handling="none",
        decisions_emitted=["allow"],
        entrypoint="x:Y",
    )
    base.update(over)
    return Manifest.model_validate(base)


def test_manifest_rules():
    assert _manifest().key == "demo-guard@1.0.0"
    with pytest.raises(ValidationError):
        _manifest(id="Not_Kebab")
    with pytest.raises(ValidationError):
        _manifest(version="1.0")
    with pytest.raises(ValidationError):
        _manifest(entrypoint=None)  # local needs an entrypoint
    with pytest.raises(ValidationError):
        _manifest(kind="remote", entrypoint=None)  # remote needs remote spec
    with pytest.raises(ValidationError):
        _manifest(decisions_emitted=["modify"])  # emits modify without capability
    with pytest.raises(ValidationError):
        _manifest(capabilities={"emits_modify": True, "parallel_safe": True})
    with pytest.raises(ValidationError):
        _manifest(sdk_version=">=2.0")
    with pytest.raises(ValidationError):
        _manifest(unknown_field=1)
