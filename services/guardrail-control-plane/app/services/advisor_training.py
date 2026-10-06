"""Labelled training data for the local advisor, from what people decided.

    python -m app.cli advisor-training-set --out advisor-set.jsonl [--days 30] [--tenant acme]
                                           [--include-released]

The gateway audits the advisor question's features (derived only: counts, shapes, codes, never
text) whenever advisors ran (`risk.advisors.features`, gateway 0.10+). This joins them with the
outcome a person chose for the same request:

    label 1  a reviewer rejected the held request, or the user rejected the confirmation
             (USER_REJECTED)
    label 0  a reviewer approved it, or the user confirmed it (EVIDENCE_USER_CONFIRMATION)
    weak 0   released without a person deciding (only with --include-released; noisy, so the
             calibrator leaves these out unless asked). A bare VERIFIED counts here: it also
             covers machine-only evidence such as a SQL dry run, so it isn't a person's "yes"

Requests that expired unreviewed, or that nobody decided, are skipped: no label is better than a
guessed one. Feed the file to the gateway's `python -m app.advise.calibrate`.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from ..store.base import Store
from .analytics import Fetch, build_filter

TRAINING_SQL = """
SELECT e.request_id, e.tenant_id, e.outcome, e.reason_codes, e.risk->'advisors'->'features' AS features
  FROM audit.audit_events e
 WHERE {where} AND jsonb_typeof(e.risk->'advisors'->'features') = 'object'
 ORDER BY e.created_at
"""

POSITIVE_CODES = frozenset({"USER_REJECTED"})
NEGATIVE_CODES = frozenset({"EVIDENCE_USER_CONFIRMATION"})  # a person confirmed it
RELEASED = frozenset({"allow", "allow_restricted", "modify"})


def _json(v: Any) -> Any:
    return json.loads(v) if isinstance(v, (str, bytes)) else v


async def training_set(
    fetch: Fetch,
    store: Store,
    *,
    since: datetime,
    tenant_id: str | None = None,
    include_released: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    params: dict[str, Any] = {"since": since}
    if tenant_id is not None:
        params["tenant_id"] = tenant_id
    rows = await fetch(TRAINING_SQL.format(where=build_filter(None, tenant_id)), params)

    decided: dict[tuple[str, str], str] = {}  # (tenant, request_id) -> approved | rejected
    for status in ("approved", "rejected"):
        for r in await store.list_reviews(tenant_id, status=status, limit=1_000_000):
            decided[(r.tenant_id, r.request_id)] = status

    out: list[dict[str, Any]] = []
    counts = {"rows": len(rows), "positive": 0, "negative": 0, "weak": 0, "skipped": 0}
    for row in rows:
        features = _json(row["features"])
        codes = set(row.get("reason_codes") or [])
        review = decided.get((row["tenant_id"], row["request_id"]))
        label: int | None
        weak = False
        if review == "rejected" or codes & POSITIVE_CODES:
            label = 1
        elif review == "approved" or codes & NEGATIVE_CODES:
            label = 0
        elif include_released and row.get("outcome") in RELEASED:
            label, weak = 0, True
        else:
            label = None
        if label is None or not isinstance(features, dict):
            counts["skipped"] += 1
            continue
        counts["weak" if weak else ("positive" if label else "negative")] += 1
        out.append(
            {
                "request_id": row["request_id"],
                "tenant_id": row["tenant_id"],
                "label": label,
                "weak": weak,
                "source": "review" if review else ("user" if codes & (POSITIVE_CODES | NEGATIVE_CODES) else "released"),
                "features": features,
            }
        )
    return out, counts
