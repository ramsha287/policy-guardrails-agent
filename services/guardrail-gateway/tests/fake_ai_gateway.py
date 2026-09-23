"""In-memory stand-in for instant-redaction-service (regex detection, replace mode)."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

BASE = "http://ai-gw:8001"
PREFIX = f"{BASE}/ai-gateway/redact/api"
PATTERNS = {
    "EMAIL_ADDRESS": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "PHONE_NUMBER": re.compile(r"\+?\d[\d ]{8,}\d"),
}


def analyse(text: str) -> tuple[str, list[dict[str, Any]]]:
    findings = []
    for etype, rx in PATTERNS.items():
        findings += [
            {"entity_type": etype, "start": m.start(), "end": m.end(), "score": 0.95} for m in rx.finditer(text)
        ]
    redacted = text
    for etype, rx in PATTERNS.items():
        redacted = rx.sub(f"[{etype}]", redacted)
    return redacted, sorted(findings, key=lambda f: f["start"])


def _json(data: Any, path: str, findings: list[dict[str, Any]]) -> Any:
    if isinstance(data, str):
        red, fs = analyse(data)
        findings += [{**f, "path": path} for f in fs]
        return red if fs else data
    if isinstance(data, dict):
        return {k: _json(v, f"{path}.{k}", findings) for k, v in data.items()}
    if isinstance(data, list):
        return [_json(v, f"{path}[{i}]", findings) for i, v in enumerate(data)]
    return data


def handle(request: httpx.Request) -> httpx.Response:
    assert request.headers.get("X-API-Key") == "engine-key"
    body = json.loads(request.content)
    path = request.url.path
    if path.endswith("/text/batch"):
        results = []
        for item in body["items"]:
            red, fs = analyse(item["text"])
            results.append({"id": item["id"], "redacted_text": red, "redacted": bool(fs), "findings": fs})
        return httpx.Response(200, json={"results": results, "offsets_basis": "normalized_text"})
    if path.endswith("/json"):
        findings: list[dict[str, Any]] = []
        data = _json(body["data"], "$", findings)
        out: dict[str, Any] = {"data": data, "redacted": bool(findings)}
        if request.url.params.get("include_findings") == "true":
            out["findings"] = findings
        return httpx.Response(200, json=out)
    if path.endswith("/text"):
        red, fs = analyse(body["text"])
        return httpx.Response(200, json={"redacted_text": red, "redacted": bool(fs), "findings": fs})
    return httpx.Response(404, json={"error": "not found"})
