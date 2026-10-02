"""Verification: close a specific assurance gap with the cheapest evidence that does it.

"Not confident enough" always means one of five dimensions is short:

    identity       is this really that agent?                   (key binding today; attestation later)
    authorization  did the person with the right actually want this?
    resource       do we know what this touches?                (e.g. an EXPLAIN row estimate)
    behaviour      is this consistent with the agent and mission?
    effect         do we know what will happen if we allow it?

`required()` says what an action class needs, `current()` what the context and evidence already
give, and the planner (app/verify/planner.py) picks verifiers for the difference. Everything here
is deterministic; no model is asked anything.

Evidence is bound to one request (`request_hash`), expires after a few minutes and is used once,
so a confirmation for "send report.pdf to ann@acme.com" can't be replayed for anything else.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from app.context.descriptors import ActionDescriptor

Dim = Literal["identity", "authorization", "resource", "behaviour", "effect"]
DIMS: tuple[Dim, ...] = ("identity", "authorization", "resource", "behaviour", "effect")
Levels = dict[str, int]  # Dim -> level

EVIDENCE_TTL_SECONDS = 10 * 60
VERIFICATION_TTL_SECONDS = 10 * 60


def request_hash(
    *, tenant: str, agent_id: str, stage: str, action: str, resource: str | None, user_id: str | None,
    session_id: str | None, payload_sha256: str, request_sha256: str = "",
) -> str:  # fmt: skip
    """Identity of "this exact request". A retry with the same body gets the same hash.

    `request_sha256` covers every other field the decision reads (request-level `arguments`,
    `tool_metadata`, classification, delegation chain), so nothing the summary or the dry run was
    built from can be swapped after a confirmation.
    """
    parts = [tenant, agent_id, stage, action, resource or "", user_id or "", session_id or "", payload_sha256,
             request_sha256]  # fmt: skip
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Evidence:
    kind: str  # dry_run | user_confirmation | human_approval
    request_hash: str
    passed: bool
    strength: dict[str, int]  # dimension -> level this evidence establishes
    detail: dict[str, Any]
    issued_at: float
    expires_at: float
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @staticmethod
    def from_json(raw: str) -> Evidence:
        d = json.loads(raw)
        return Evidence(**d)


@dataclass(frozen=True)
class Verification:
    """A pending request for evidence that only a person can give (user confirmation)."""

    id: str
    tenant_id: str
    request_hash: str
    kind: str
    agent_id: str
    user_id: str | None
    summary: str
    status: Literal["pending", "confirmed", "rejected", "expired"]
    created_at: float
    expires_at: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @staticmethod
    def from_json(raw: str) -> Verification:
        return Verification(**json.loads(raw))


def required(d: ActionDescriptor, codes: Iterable[str], environment: str) -> Levels:
    """What this action needs before it may run without a human. Only asked when the decision
    table said `verify` (high risk, or an elevated external write)."""
    codes = set(codes)
    need: Levels = {}
    if d.kind == "sql" and d.verb == "read":
        need["resource"] = 2
        need["effect"] = 1
    if d.writes and d.destination == "external":
        need["authorization"] = 2
    if d.verb in ("delete", "admin", "execute"):
        need["authorization"] = 2
        need["effect"] = 1
    if not d.parsed:
        need["authorization"] = 2
    if "TAINTED_SESSION" in codes:
        need["behaviour"] = 1
    if environment == "production":
        need["identity"] = 1
    if not need:  # high risk for reasons no machine check addresses: ask the person
        need["authorization"] = 2
    return need


def current(*, assurance: str, d: ActionDescriptor, codes: Iterable[str], evidence: Iterable[Evidence]) -> Levels:
    codes = set(codes)
    have: Levels = {
        "identity": 1 if assurance in ("A1", "A2", "A3", "A4") else 0,
        "authorization": 0,
        "resource": 1 if d.parsed and d.target else 0,
        "behaviour": 0 if codes & {"TAINTED_SESSION", "REPEATED_DENIALS"} else 1,
        "effect": 0,
    }
    for ev in evidence:
        if ev.passed:
            for dim, lvl in ev.strength.items():
                if dim in have:
                    have[dim] = max(have[dim], int(lvl))
    return have


def gap(need: Mapping[str, int], have: Mapping[str, int]) -> Levels:
    return {dim: lvl for dim, lvl in need.items() if have.get(dim, 0) < lvl}


def summary_for(agent_id: str, d: ActionDescriptor) -> str:
    """What the person is asked to confirm, built only from the descriptor (names, never values)."""
    if d.kind == "sql":
        rows = f"up to {d.rows_requested} rows" if d.rows_requested is not None else "all matching rows"
        cols = f" ({', '.join(d.columns[:6])})" if d.columns else ""
        return f"{agent_id} wants to {d.verb} {rows}{cols} from {', '.join(d.tables) or d.target or 'a database'}"
    if d.kind in ("http", "message") and d.destination_host:
        return f"{agent_id} wants to {d.verb} data to {d.destination_host} ({d.destination or 'unknown'} destination)"
    if d.kind == "file":
        return f"{agent_id} wants to {d.verb} {d.target or 'a file'}"
    return f"{agent_id} wants to run a {d.verb} action on {d.target or 'an unrecognised tool'}"
