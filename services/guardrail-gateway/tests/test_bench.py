"""The fast-path latency benchmark runs the real decision path and reports what Gate 1 needs."""

import asyncio
import json

from app.bench import GATE_P99_MS, main, run, summarise


def test_summary_percentiles():
    s = summarise([float(i) for i in range(1, 101)])
    assert (s["n"], s["p50_ms"], s["p99_ms"], s["max_ms"]) == (100, 50.0, 99.0, 100.0)
    assert summarise([])["p99_ms"] == 0.0


def test_benchmark_runs_low_risk_traffic_through_the_whole_path():
    out = asyncio.run(
        run(
            n=60,
            profile="content",
            opa_url=None,
            concurrency=1,
            budget_ms=GATE_P99_MS,
            advisors_json='[{"name":"local","provider":"local","mode":"enforce"}]',
            warmup=20,
        )
    )
    assert out["bands"] == {"low": 60} and out["outcomes"] == {"allow": 60}  # it is the fast path
    assert set(out["stages"]) == {"input", "retrieval", "tool", "output"}
    assert out["overall"]["n"] == 60 and out["throughput_rps"] > 0
    assert "no OPA hop" in out["policy"] and out["within_budget"] is None  # never mistaken for a gate result
    assert out["p99_under_budget"] in (True, False)


def test_cli_writes_a_report_and_can_fail_the_build(tmp_path, capsys):
    report = tmp_path / "bench.json"
    assert main(["--n", "20", "--profile", "core", "--report", str(report), "--advisors", ""]) == 0
    assert json.loads(report.read_text())["profile"] == "core"
    assert (
        main(["--n", "20", "--profile", "core", "--budget-ms", "0.000001", "--fail-over-budget", "--advisors", ""]) == 1
    )
