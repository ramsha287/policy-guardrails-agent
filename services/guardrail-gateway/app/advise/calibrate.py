"""Calibrate the local advisor on your own labelled decisions.

    python -m app.advise.calibrate --data advisor-set.jsonl --out app/advise/models/local-v2.json \
        [--holdout 0.2] [--include-weak] [--min-auc 0.75] [--report calibration.json]

The data comes from `python -m app.cli advisor-training-set` on the control plane: one JSON line
per request on which advisors ran, with the features the gateway audited (derived only: counts,
shapes, codes, never text) and a label from what people decided:

    {"request_id": "...", "tenant_id": "...", "label": 1, "weak": false, "features": {...}}

label 1 = a reviewer rejected the held request, or the user rejected the confirmation;
label 0 = a reviewer approved it, or the user confirmed it. `weak` rows are requests released
without anyone looking (label 0); they are left out unless --include-weak.

It fits a logistic model on the features (`vectorize()` in providers/local.py, so the gateway
scores exactly what was trained), holds out a deterministic share of requests, and reports on the
held-out part, next to the weights you run today: AUC, precision and recall at each threshold,
Brier score and expected calibration error (ECE). Read the report before swapping weights; run
the new file in shadow mode first (ADVISORS_JSON options.weights_path).

Reviewer labels say "this request should have been stopped", not which question was at stake, so
both questions get the same model unless a row carries per-question labels
({"labels": {"exfiltration": 1, "injection": 0}}).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.advise.contract import QUESTIONS, Features
from app.advise.providers.local import LocalModel, QuestionModel, load_model, vectorize

MIN_ROWS = 50
MIN_POSITIVES = 10


@dataclass(frozen=True)
class Row:
    request_id: str
    x: dict[str, float]
    labels: dict[str, int]  # question -> 0/1
    weak: bool


def _features(raw: dict[str, Any]) -> Features | None:
    known = {k: v for k, v in raw.items() if k in Features.model_fields}  # newer gateways may add fields
    try:
        return Features.model_validate(known)
    except ValueError:
        return None


def load_rows(path: Path, *, include_weak: bool) -> tuple[list[Row], int]:
    rows, skipped = [], 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        if not isinstance(raw, dict):
            skipped += 1
            continue
        f = _features(raw.get("features") or {})
        weak = bool(raw.get("weak"))
        if f is None or (weak and not include_weak):
            skipped += 1
            continue
        per_q = raw.get("labels") or {}
        labels = {q: int(per_q.get(q, raw.get("label", 0))) for q in QUESTIONS}
        rows.append(Row(str(raw.get("request_id") or len(rows)), vectorize(f), labels, weak))
    return rows, skipped


def in_holdout(request_id: str, share: float) -> bool:
    """Deterministic split by request id, so a rerun on the same data gives the same report."""
    h = int(hashlib.sha256(request_id.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return h < share


def _sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-max(-40.0, min(40.0, z))))


def _solve(a: list[list[float]], b: list[float]) -> list[float]:
    """Gaussian elimination with partial pivoting (a is small: one row per feature)."""
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(m[r][col]))
        m[col], m[piv] = m[piv], m[col]
        d = m[col][col]
        if abs(d) < 1e-12:
            continue
        for r in range(col + 1, n):
            f = m[r][col] / d
            if f:
                for c in range(col, n + 1):
                    m[r][c] -= f * m[col][c]
    x = [0.0] * n
    for r in range(n - 1, -1, -1):
        d = m[r][r]
        x[r] = 0.0 if abs(d) < 1e-12 else (m[r][n] - sum(m[r][c] * x[c] for c in range(r + 1, n))) / d
    return x


def fit(
    xs: list[dict[str, float]], ys: list[int], *, l2: float = 1.0, iterations: int = 50
) -> tuple[float, dict[str, float]]:
    """L2-regularised logistic regression by Newton's method (IRLS) with step halving.

    Converges in a handful of iterations whatever the feature scale, and the probabilities stay
    calibrated (no class re-weighting; the report measures calibration). The bias isn't
    regularised. Dependency-free on purpose: the model is ~45 weights."""
    names = sorted({k for x in xs for k in x})
    d = len(names) + 1  # index 0 = bias
    index = {k: j + 1 for j, k in enumerate(names)}
    rows = [[(0, 1.0), *((index[k], v) for k, v in x.items() if v)] for x in xs]
    theta = [0.0] * d

    def loss(t: list[float]) -> float:
        total = 0.5 * l2 * sum(v * v for v in t[1:])
        for r, y in zip(rows, ys, strict=True):
            z = sum(t[j] * v for j, v in r)
            total += math.log1p(math.exp(-abs(z))) + max(z, 0.0) - y * z  # stable log-loss
        return total

    current = loss(theta)
    for _ in range(iterations):
        grad = [0.0] + [l2 * v for v in theta[1:]]
        hess = [[0.0] * d for _ in range(d)]
        for j in range(1, d):
            hess[j][j] = l2
        hess[0][0] = 1e-6
        for r, y in zip(rows, ys, strict=True):
            p = _sigmoid(sum(theta[j] * v for j, v in r))
            g, h = p - y, p * (1 - p)
            for j, v in r:
                grad[j] += g * v
                hj = hess[j]
                for k, u in r:
                    hj[k] += h * v * u
        step = _solve(hess, grad)
        scale = 1.0
        for _ in range(20):  # halve until the loss goes down
            cand = [t - scale * s for t, s in zip(theta, step, strict=True)]
            new = loss(cand)
            if new <= current:
                break
            scale /= 2
        else:
            break
        theta, moved, current = cand, max(abs(scale * s) for s in step), new
        if moved < 1e-6:
            break
    return round(theta[0], 4), {k: round(theta[index[k]], 4) for k in names if abs(theta[index[k]]) >= 1e-4}


def auc(probs: list[float], ys: list[int]) -> float | None:
    """Probability a random positive scores above a random negative (ties count half)."""
    pos = [p for p, y in zip(probs, ys, strict=True) if y]
    neg = [p for p, y in zip(probs, ys, strict=True) if not y]
    if not pos or not neg:
        return None
    ranked = sorted([(p, 1) for p in pos] + [(p, 0) for p in neg])
    rank_sum, i = 0.0, 0
    while i < len(ranked):
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        avg = (i + j + 1) / 2  # 1-based average rank of the tie group
        rank_sum += avg * sum(1 for k in range(i, j) if ranked[k][1])
        i = j
    return round((rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)), 4)


def calibration(probs: list[float], ys: list[int], bins: int = 10) -> dict[str, Any]:
    n = len(probs)
    brier = sum((p - y) ** 2 for p, y in zip(probs, ys, strict=True)) / n if n else None
    ece = 0.0
    table = []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i, p in enumerate(probs) if lo <= p < hi or (b == bins - 1 and p == 1.0)]
        if not idx:
            continue
        conf = sum(probs[i] for i in idx) / len(idx)
        acc = sum(ys[i] for i in idx) / len(idx)
        ece += len(idx) / n * abs(conf - acc)
        table.append(
            {"bin": f"{lo:.1f}-{hi:.1f}", "n": len(idx), "mean_p": round(conf, 3), "positive_rate": round(acc, 3)}
        )
    return {"brier": round(brier, 4) if brier is not None else None, "ece": round(ece, 4), "bins": table}


def at_threshold(probs: list[float], ys: list[int], t: float) -> dict[str, Any]:
    tp = sum(1 for p, y in zip(probs, ys, strict=True) if p >= t and y)
    fp = sum(1 for p, y in zip(probs, ys, strict=True) if p >= t and not y)
    fn = sum(1 for p, y in zip(probs, ys, strict=True) if p < t and y)
    return {
        "threshold": t,
        "flagged": tp + fp,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
    }


def evaluate(model: QuestionModel, xs: list[dict[str, float]], ys: list[int]) -> dict[str, Any]:
    probs = [_sigmoid(model.bias + sum(w * x.get(k, 0.0) for k, w in model.weights.items())) for x in xs]
    return {
        "n": len(ys),
        "positives": sum(ys),
        "auc": auc(probs, ys),
        **calibration(probs, ys),
        "at_suspicious": at_threshold(probs, ys, model.suspicious_at),
        "at_malicious": at_threshold(probs, ys, model.malicious_at),
    }


def calibrate(
    rows: list[Row], *, holdout: float, baseline: LocalModel | None, version: str, source: str
) -> tuple[LocalModel, dict[str, Any]]:
    train = [r for r in rows if not in_holdout(r.request_id, holdout)]
    test = [r for r in rows if in_holdout(r.request_id, holdout)]
    questions: dict[str, QuestionModel] = {}
    report: dict[str, Any] = {"rows": len(rows), "train": len(train), "holdout": len(test), "questions": {}}
    for q in QUESTIONS:
        ytr = [r.labels[q] for r in train]
        if len(train) < MIN_ROWS or sum(ytr) < MIN_POSITIVES or len(ytr) - sum(ytr) < MIN_POSITIVES:
            raise ValueError(
                f"{q}: not enough labelled data to train ({len(train)} rows, {sum(ytr)} positive; "
                f"need {MIN_ROWS} rows with at least {MIN_POSITIVES} of each label)"
            )
        bias, weights = fit([r.x for r in train], ytr)
        prev = baseline.questions.get(q) if baseline else None
        m = QuestionModel(
            bias=bias,
            weights=weights,
            suspicious_at=prev.suspicious_at if prev else 0.5,
            malicious_at=prev.malicious_at if prev else 0.8,
            verify_at=prev.verify_at if prev else 1.0,
        )
        questions[q] = m
        xte, yte = [r.x for r in test], [r.labels[q] for r in test]
        entry: dict[str, Any] = {"trained": evaluate(m, xte, yte) if test else None}
        if prev is not None and test:
            entry["current_weights"] = evaluate(prev, xte, yte)
        report["questions"][q] = entry
    model = LocalModel(
        version=version,
        questions=questions,
        trained_on={
            "source": source,
            "rows": len(train),
            "positives": {q: sum(r.labels[q] for r in train) for q in QUESTIONS},
            "holdout_share": holdout,
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
        },
    )
    return model, report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.advise.calibrate", description="Calibrate the local advisor.")
    p.add_argument("--data", type=Path, required=True, help="JSONL from `app.cli advisor-training-set`")
    p.add_argument("--out", type=Path, required=True, help="where to write the new weights file")
    p.add_argument("--version", default=None, help="model version (default: local-<date>)")
    p.add_argument("--baseline", type=Path, default=None, help="weights to compare with (default: the shipped file)")
    p.add_argument("--holdout", type=float, default=0.2)
    p.add_argument("--include-weak", action="store_true", help="use released, unreviewed requests as negatives")
    p.add_argument("--min-auc", type=float, default=None, help="exit 1 if any question's held-out AUC is lower")
    p.add_argument("--report", type=Path, default=None)
    a = p.parse_args(argv)
    if not 0.05 <= a.holdout <= 0.5:
        p.error("--holdout must be between 0.05 and 0.5")
    rows, skipped = load_rows(a.data, include_weak=a.include_weak)
    try:
        model, report = calibrate(
            rows,
            holdout=a.holdout,
            baseline=load_model(a.baseline) if a.baseline else load_model(),
            version=a.version or f"local-{datetime.now(UTC):%Y%m%d}",
            source=a.data.name,
        )
    except ValueError as exc:
        print(f"calibration refused: {exc}", file=sys.stderr)
        return 2
    report["skipped_rows"] = skipped
    a.out.write_text(json.dumps(model.model_dump(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    text = json.dumps(report, indent=2)
    print(text)
    if a.report:
        a.report.write_text(text + "\n", encoding="utf-8")
    if a.min_auc is not None:
        aucs = [(e["trained"] or {}).get("auc") for e in report["questions"].values()]
        if any(x is None or x < a.min_auc for x in aucs):
            print(f"held-out AUC below {a.min_auc}: {aucs}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
