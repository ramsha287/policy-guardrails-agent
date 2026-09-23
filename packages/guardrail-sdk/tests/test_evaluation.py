import json
import re

import httpx

from guardrail_sdk import (
    Decision,
    EnvSecretReader,
    Finding,
    Guardrail,
    GuardrailResult,
    Manifest,
    Payload,
    PluginContext,
    SecurityContext,
)
from guardrail_sdk.cli import main as cli_main
from guardrail_sdk.evaluation import evaluate, load_dataset, meets, report

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


class EmailOnly(Guardrail):
    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        text = json.dumps(payload.model_dump(mode="json"))
        if "RAISE" in text:
            raise RuntimeError("boom")
        hits = EMAIL.findall(text)
        if hits:
            return GuardrailResult(decision=Decision.BLOCK, reason="email", findings=[Finding(type="EMAIL")])
        return GuardrailResult(decision=Decision.ALLOW, reason="clean")


MANIFEST = Manifest.model_validate(
    dict(
        id="email-only",
        version="1.0.0",
        kind="local",
        stages=["input", "tool"],
        description="d",
        owner="o",
        data_handling="none",
        decisions_emitted=["allow", "block"],
        entrypoint="tests.test_evaluation:EmailOnly",
    )
)


def write(tmp_path, rows):
    p = tmp_path / "ds.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return p


ROWS = [
    {"id": "a", "stage": "input", "label": "pii", "payload": {"text": "mail a@b.com"}},  # TP
    {"id": "b", "stage": "input", "label": "pii", "payload": {"text": "SSN 123-45-6789"}},  # FN
    {"id": "c", "stage": "input", "label": "clean", "payload": {"text": "hello"}},  # TN
    {"id": "d", "stage": "input", "label": "clean", "payload": {"text": "x@y.com is ok"}},  # FP
    {"id": "e", "stage": "tool", "label": "pii", "payload": {"tool_call": {"name": "t", "result": "c@d.com"}}},
    {
        "id": "f",
        "stage": "tool",
        "label": "clean",
        "payload": {"tool_call": {"name": "t", "arguments": {"q": "RAISE"}}},
    },
    {"id": "g", "stage": "output", "label": "pii", "payload": {"text": "skipped: stage not supported"}},
]


async def test_metrics(tmp_path):
    g = EmailOnly(MANIFEST, PluginContext(http=httpx.AsyncClient(), secrets=EnvSecretReader()))
    per_stage = await evaluate(g, load_dataset(write(tmp_path, ROWS)))
    inp = per_stage["input"]
    assert (inp.tp, inp.fn, inp.tn, inp.fp) == (1, 1, 1, 1)
    assert inp.precision == 0.5 and inp.recall == 0.5
    assert inp.misses == ["b"] and inp.false_alarms == ["d"]
    assert per_stage["tool"].tp == 1 and per_stage["tool"].errors == 1
    assert "output" not in per_stage
    rep = report(per_stage, MANIFEST.key)
    assert rep["overall"]["cases"] == 5 and rep["stages"]["tool"]["error_cases"] == ["f"]
    problems = meets(per_stage, 0.9, 0.9, 2)
    assert any("tool: 1 case(s) raised errors" in p for p in problems)
    assert any("input: precision" in p for p in problems)


def test_cli_evaluate_exit_code(tmp_path, monkeypatch, capsys):
    manifest = tmp_path / "guardrail.yaml"
    manifest.write_text(json.dumps(MANIFEST.model_dump(mode="json")))  # JSON is valid YAML
    ds = write(tmp_path, ROWS[:1])
    cfg = tmp_path / "cfg.json"
    cfg.write_text("{}")
    rc = cli_main(
        [
            "evaluate",
            "--manifest",
            str(manifest),
            "--config",
            str(cfg),
            "--dataset",
            str(ds),
            "--min-cases",
            "1",
            "--min-precision",
            "0.9",
            "--min-recall",
            "0.9",
        ]
    )
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["thresholds"]["passed"] is True
    rc = cli_main(["evaluate", "--manifest", str(manifest), "--dataset", str(ds), "--min-cases", "200"])
    assert rc == 1


def test_committed_dataset_meets_requirement_d():
    from pathlib import Path

    path = Path(__file__).resolve().parents[3] / "eval" / "datasets" / "pii_v1.jsonl"
    cases = load_dataset(path)
    by_stage = {}
    for c in cases:
        by_stage.setdefault(c.stage.value, []).append(c)
    assert set(by_stage) == {"input", "output", "retrieval", "tool"}
    for stage, cs in by_stage.items():
        assert len(cs) >= 200, stage
        assert sum(c.label for c in cs) == len(cs) // 2
