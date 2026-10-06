"""The advisor plug-in contract.

An advisor answers one narrow, typed question about a request that is already in the uncertain
risk band. It never sees the request's text and it never decides:

- **Typed question, trusted fields only.** The question is built here from the action descriptor,
  the session state, the risk assessment and *derived* content features (sizes, counts, guardrail
  finding types). Payload text, tool results and argument values never go in, so content the agent
  fetched can't instruct the advisor that judges acting on it.
- **Typed, bounded answer.** `label` (benign | suspicious | malicious), `confidence` and an
  optional `verify` request. Anything else (extra fields, wrong types, out of range, too slow, an
  exception) counts as "no signal".
- **Only tighten.** An answer can add capped risk points or ask for verification. Nothing an advisor
  returns can permit a request, lower a score or cancel a verification (see panel.py).

Questions:

    exfiltration   is this action likely moving sensitive data out of the organisation?
    injection      is this action likely driven by instructions from untrusted content
                   rather than by the user's task?
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Sequence
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from app.context.descriptors import ActionDescriptor, _as_ip
from app.risk.engine import Assessment
from app.session.store import SessionView
from guardrail_sdk import GuardrailOutcome, Payload

QuestionKind = Literal["exfiltration", "injection"]
QUESTIONS: tuple[QuestionKind, ...] = ("exfiltration", "injection")
Label = Literal["benign", "suspicious", "malicious"]

_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_BLOB = re.compile(r"[A-Za-z0-9+/=_-]{48,}")
_TOOL_NAME = re.compile(r"[^a-z0-9._-]+")
_SCAN_LIMIT = 256 * 1024  # bytes of content looked at for counts; the rest is only measured


class Features(BaseModel):
    """Everything an advisor may know about the request. All of it is derived, none of it is text."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    stage: str
    environment: str
    data_classification: str
    assurance: str
    tool_name: str | None = None  # normalised to [a-z0-9._-], at most 64 characters
    is_tool_result: bool = False
    # action descriptor
    kind: str
    verb: str
    parsed: bool
    destination: str | None = None  # internal | external
    statements: int = 1
    rows_requested: int | None = None
    has_filter: bool | None = None
    # destination host, as shape only (the name itself is attacker-controlled)
    host_is_ip: bool = False
    host_labels: int = 0
    host_lookalike_internal: bool = False  # mentions an internal domain but isn't under it
    first_seen_target: bool | None = None
    # session
    session_labels: tuple[str, ...] = ()
    session_steps: int = 0
    session_denials: int = 0
    session_age_seconds: float = 0.0
    # deterministic risk
    risk_score: int
    risk_band: str
    risk_codes: tuple[str, ...] = ()
    trust: int
    confidence: float
    # content, as counts and sizes
    payload_bytes: int = 0
    url_count: int = 0
    email_count: int = 0
    ip_literal_count: int = 0
    encoded_blob: bool = False
    url_query_bytes: int = 0  # bytes carried in URL query strings (data smuggled in a GET)
    finding_types: tuple[str, ...] = ()
    max_finding_score: float = 0.0
    guardrail_flags: tuple[str, ...] = ()  # non-allow guardrail decisions, e.g. ("modify",)


class Question(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: QuestionKind
    tenant_id: str
    agent_id: str
    features: Features

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


class Answer(BaseModel):
    """What an advisor returns. Validated strictly: anything else is no signal."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    label: Label
    confidence: float = Field(ge=0.0, le=1.0)
    verify: bool = False  # "a person should confirm this"; ignored for benign answers


class Advisor(Protocol):
    """A provider. `hosted` = the question leaves the gateway (tenant data policy applies)."""

    name: str
    hosted: bool

    async def ask(self, question: Question) -> Answer | dict[str, Any]: ...

    async def close(self) -> None: ...


def points_for(answer: Answer, cap: int) -> int:
    """malicious -> up to the cap, suspicious -> up to half of it, benign -> 0 (never negative)."""
    weight = {"benign": 0.0, "suspicious": 0.5, "malicious": 1.0}[answer.label]
    return max(0, min(cap, round(cap * weight * answer.confidence)))


# ---- building the question ------------------------------------------------------------------------


def _strings(value: Any, budget: list[int]) -> Iterator[str]:
    if budget[0] <= 0:
        return
    if isinstance(value, str):
        budget[0] -= len(value)
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k, budget)
            yield from _strings(v, budget)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v, budget)


def content_of(payload: Payload) -> tuple[Any, ...]:
    """The parts of a payload the current action carries (for a tool call: its arguments)."""
    tc = payload.tool_call
    if tc is not None:
        return (tc.arguments,) if tc.result is None else (tc.arguments, tc.result)
    parts: list[Any] = []
    if payload.text is not None:
        parts.append(payload.text)
    if payload.messages:
        parts.append([m.content for m in payload.messages])
    if payload.chunks:
        parts.append([c.model_dump(mode="json") for c in payload.chunks])
    return tuple(parts)


def _lookalike(host: str, internal_domains: Sequence[str]) -> bool:
    h = host.lower().rstrip(".")
    for d in internal_domains:
        d = d.lower().lstrip(".")
        if not d or h == d or h.endswith("." + d):
            continue
        stem = d.split(".")[0]
        if d in h or (len(stem) >= 4 and stem in h.replace("-", "").replace(".", "")):
            return True
    return False


def build_features(
    *,
    stage: str,
    environment: str,
    data_classification: str,
    assurance: str,
    payload: Payload,
    descriptor: ActionDescriptor,
    view: SessionView,
    assessment: Assessment,
    results: Iterable[GuardrailOutcome],
    internal_domains: Sequence[str] = (),
) -> Features:
    budget = [_SCAN_LIMIT]
    parts = content_of(payload)
    texts = [s for p in parts for s in _strings(p, budget)]
    joined = "\n".join(texts)
    urls = _URL.findall(joined)
    query_bytes = sum(len(u.split("?", 1)[1]) for u in urls if "?" in u)
    try:
        size = len(json.dumps(parts, default=str))
    except (TypeError, ValueError):
        size = len(joined)
    host = descriptor.destination_host or ""
    findings = [f for r in results for f in r.findings]
    tc = payload.tool_call
    return Features(
        stage=stage,
        environment=environment,
        data_classification=data_classification,
        assurance=assurance,
        tool_name=_TOOL_NAME.sub("_", tc.name.lower())[:64] if tc else None,
        is_tool_result=bool(tc is not None and tc.result is not None),
        kind=descriptor.kind,
        verb=descriptor.verb,
        parsed=descriptor.parsed,
        destination=descriptor.destination,
        statements=descriptor.statements,
        rows_requested=descriptor.rows_requested,
        has_filter=descriptor.has_filter,
        host_is_ip=bool(host) and _as_ip(host) is not None,
        host_labels=len([p for p in host.split(".") if p]) if host else 0,
        host_lookalike_internal=bool(host)
        and descriptor.destination == "external"
        and _lookalike(host, internal_domains),
        first_seen_target=view.first_seen_target,
        session_labels=tuple(sorted(view.labels)),
        session_steps=view.steps,
        session_denials=max(view.denials, view.agent_recent_denials),
        session_age_seconds=round(view.age_seconds, 1),
        risk_score=assessment.score,
        risk_band=assessment.band,
        risk_codes=tuple(assessment.codes),
        trust=assessment.trust,
        confidence=assessment.confidence,
        payload_bytes=size,
        url_count=len(urls),
        email_count=len(_EMAIL.findall(joined)),
        ip_literal_count=len(_IP.findall(joined)),
        encoded_blob=bool(_BLOB.search(joined)),
        url_query_bytes=query_bytes,
        finding_types=tuple(sorted({f.type for f in findings}))[:20],
        max_finding_score=round(max((f.score for f in findings), default=0.0), 3),
        guardrail_flags=tuple(sorted({r.decision.value for r in results if r.decision.value != "allow"})),
    )
