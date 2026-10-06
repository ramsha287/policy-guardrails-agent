"""Calibrating the local advisor from labelled decisions (phase 9)."""

import asyncio
import json
import random

import pytest

from app.advise.calibrate import auc, calibration, in_holdout, load_rows, main
from app.advise.contract import Features, Question
from app.advise.providers.local import LocalAdvisor, load_model

BASE = dict(
    stage="tool", environment="production", data_classification="INTERNAL", assurance="A1", kind="http",
    verb="send", parsed=True, risk_score=50, risk_band="elevated", trust=70, confidence=1.0,
)  # fmt: skip


def synthetic(n=800, seed=3, noise=0.03):
    """Rows whose label follows a rule a person might apply, plus some label noise."""
    rng = random.Random(seed)
    out = []
    for i in range(n):
        external = rng.random() < 0.5
        sensitive = rng.random() < 0.4
        query = rng.choice([0, 0, 0, 300])
        f = Features(
            **BASE,
            destination="external" if external else "internal",
            session_labels=("holds:PII",) if sensitive else (),
            url_query_bytes=query,
            session_steps=rng.randint(0, 30),
        )
        bad = external and sensitive  # learnable by a linear model; label noise caps the AUC
        label = int(bad) if rng.random() > noise else int(not bad)
        out.append(
            {
                "request_id": f"r-{i}",
                "tenant_id": "acme",
                "label": label,
                "weak": False,
                "features": f.model_dump(mode="json"),
            }
        )
    return out


def write(tmp_path, rows, name="set.jsonl"):
    p = tmp_path / name
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return p


def test_metrics():
    assert auc([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0]) == 1.0
    assert auc([0.1, 0.2, 0.8, 0.9], [1, 1, 0, 0]) == 0.0
    assert auc([0.5, 0.5], [1, 0]) == 0.5 and auc([0.3], [1]) is None
    c = calibration([0.95, 0.05], [1, 0])
    assert c["ece"] == pytest.approx(0.05) and c["brier"] == pytest.approx(0.0025)
    assert in_holdout("r-1", 0.2) == in_holdout("r-1", 0.2)  # deterministic


def test_calibration_learns_reports_and_writes_a_usable_model(tmp_path, capsys):
    data = write(tmp_path, synthetic())
    out, report = tmp_path / "local-v2.json", tmp_path / "report.json"
    assert (
        main(
            [
                "--data",
                str(data),
                "--out",
                str(out),
                "--report",
                str(report),
                "--min-auc",
                "0.8",
                "--version",
                "local-test",
            ]
        )
        == 0
    )
    r = json.loads(report.read_text())
    ex = r["questions"]["exfiltration"]
    assert ex["trained"]["auc"] >= 0.8 and "current_weights" in ex and ex["trained"]["ece"] is not None
    assert r["train"] + r["holdout"] == 800
    model = load_model(out)
    assert model.version == "local-test" and model.trained_on["rows"] == r["train"]
    adv = LocalAdvisor("local", model)
    risky = Features(**BASE, destination="external", session_labels=("holds:PII",), url_query_bytes=300)
    calm = Features(**BASE, destination="internal")
    ask = lambda f: asyncio.run(adv.ask(Question(kind="exfiltration", tenant_id="t", agent_id="a", features=f)))  # noqa: E731
    assert ask(risky).label != "benign" and ask(calm).label == "benign"


def test_refuses_too_little_data_and_skips_weak_rows(tmp_path):
    rows = synthetic(40)
    assert main(["--data", str(write(tmp_path, rows)), "--out", str(tmp_path / "x.json")]) == 2
    weak = [{**r, "weak": True} for r in synthetic(100)]
    loaded, skipped = load_rows(write(tmp_path, weak, "weak.jsonl"), include_weak=False)
    assert loaded == [] and skipped == 100
    loaded, _ = load_rows(write(tmp_path, weak, "weak.jsonl"), include_weak=True)
    assert len(loaded) == 100


def test_per_question_labels_and_unknown_feature_fields(tmp_path):
    row = synthetic(1)[0]
    row["labels"] = {"exfiltration": 1, "injection": 0}
    row["features"]["added_in_a_newer_gateway"] = 7  # ignored, not fatal
    [r], _ = load_rows(write(tmp_path, [row]), include_weak=False)
    assert r.labels == {"exfiltration": 1, "injection": 0}
