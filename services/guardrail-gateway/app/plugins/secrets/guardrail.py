"""`secrets`: credentials in prompts, retrieved documents, tool calls and answers.

Finds API keys, tokens, private keys and passwords by their published formats (AWS, GitHub, Slack,
OpenAI, Anthropic, Stripe, Google, JWTs, PEM private keys, database URLs with a password, this
platform's own gk_/cpk_ keys) plus `password = ...`-style assignments whose value looks random
(Shannon entropy). Everything runs in process; nothing is sent anywhere.

What it does with a finding is configurable: redact it (`<SECRET:AWS_ACCESS_KEY>`, MODIFY) or block
the request. Types listed in `block_types` always block (a private key in a prompt is rarely
something to merely redact). Findings carry the type, offsets and location, never the value.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.plugins.common.textwalk import rewrite, walk
from guardrail_sdk import Decision, Finding, Guardrail, GuardrailResult, Payload, SecurityContext

# (type, pattern, group holding the secret: 0 = whole match). Order matters: specific before generic.
DETECTORS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
            r"[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)"
        ),
        0,
    ),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"), 0),
    (
        "AWS_SECRET_KEY",
        re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
        1,
    ),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"), 0),
    ("SLACK_TOKEN", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), 0),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), 0),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"), 0),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), 0),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0),
    ("PLATFORM_KEY", re.compile(r"\b(?:gk|cpk)_[A-Za-z0-9_-]{32,}"), 0),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), 0),
    (
        "CONNECTION_STRING",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://[^\s:/@]+:([^\s@/]+)@"
        ),
        1,
    ),
)
ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token)"
    r"\b[\"']?\s*[:=]\s*[\"']?([^\s\"',;}{]{8,4096})"
)
PLACEHOLDER = re.compile(
    r"(?i)^(?:x{4,}|\*{4,}|changeme|change_me|password\d*|secret|example\w*|your[_-]\w+|dummy\w*|test\w*|"
    r"<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%\([^)]*\)s|null|none|redacted|<secret:[a-z_]+>)$"
)
SCAN_LIMIT = 1_100_000  # characters; above max_payload_kb (1 MB), so truncation means "too large"
ALL_TYPES = (*(t for t, _, _ in DETECTORS), "PASSWORD_ASSIGNMENT")


def entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


@dataclass(frozen=True)
class Hit:
    type: str
    start: int
    end: int


def find_secrets(text: str, *, min_entropy: float = 3.0, ignore: Iterable[str] = ()) -> list[Hit]:
    """Non-overlapping hits, leftmost first; a span claimed by a specific detector isn't re-reported."""
    skip = set(ignore)
    hits: list[Hit] = []

    def free(a: int, b: int) -> bool:
        return all(b <= h.start or a >= h.end for h in hits)

    for kind, rx, group in DETECTORS:
        if kind in skip:
            continue
        for m in rx.finditer(text):
            a, b = m.span(group)
            if a < b and free(a, b):
                hits.append(Hit(kind, a, b))
    if "PASSWORD_ASSIGNMENT" not in skip:
        for m in ASSIGNMENT.finditer(text):
            value = m.group(1)
            a, b = m.span(1)
            if PLACEHOLDER.match(value) or entropy(value[:200]) < min_entropy or not free(a, b):
                continue
            hits.append(Hit("PASSWORD_ASSIGNMENT", a, b))
    return sorted(hits, key=lambda h: h.start)


def redact(text: str, hits: list[Hit]) -> str:
    out, pos = [], 0
    for h in hits:
        out.append(text[pos : h.start])
        out.append(f"<SECRET:{h.type}>")
        pos = h.end
    out.append(text[pos:])
    return "".join(out)


class SecretsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    on_detect: Literal["modify", "block"] = "modify"
    # Always block these, whatever on_detect says.
    block_types: list[str] = Field(default_factory=lambda: ["PRIVATE_KEY"])
    # Detectors to switch off (e.g. JWT in a system that passes tokens on purpose).
    ignore_types: list[str] = Field(default_factory=list)
    min_entropy: float = Field(3.0, ge=0.0, le=8.0)  # for PASSWORD_ASSIGNMENT values
    scan_tool_arguments: bool = True
    scan_tool_result: bool = True

    @field_validator("block_types", "ignore_types")
    @classmethod
    def _known(cls, v: list[str]) -> list[str]:
        unknown = sorted(set(v) - set(ALL_TYPES))
        if unknown:
            raise ValueError(f"unknown secret type(s) {unknown}; known: {', '.join(ALL_TYPES)}")
        return v


class SecretsGuardrail(Guardrail):
    config_model = SecretsConfig
    config: SecretsConfig

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        c = self.config
        # Scan everything the manifest admits (max_payload_kb); anything beyond can't be vouched for.
        w = walk(payload, tool_arguments=c.scan_tool_arguments, tool_result=c.scan_tool_result, limit=SCAN_LIMIT)
        if w.truncated:
            return GuardrailResult(
                decision=Decision.BLOCK,
                reason="payload too large to scan for credentials (fail closed)",
                risk_score=50,
                metadata={"truncated": True},
            )
        findings: list[Finding] = []
        rewritten: dict[tuple, str] = {}
        types: set[str] = set()
        for span in w.spans:
            hits = find_secrets(span.text, min_entropy=c.min_entropy, ignore=c.ignore_types)
            if not hits:
                continue
            types.update(h.type for h in hits)
            findings.extend(
                Finding(type=h.type, score=1.0, start=h.start, end=h.end, location=span.location) for h in hits
            )
            rewritten[span.key] = redact(span.text, hits)
        meta: dict[str, object] = {}
        if not findings:
            return GuardrailResult(decision=Decision.ALLOW, reason="no secrets found", metadata=meta)
        summary = ", ".join(sorted(types))
        if c.on_detect == "block" or types & set(c.block_types):
            return GuardrailResult(
                decision=Decision.BLOCK,
                reason=f"credentials found ({summary})",
                risk_score=90,
                findings=findings,
                metadata=meta,
            )
        return GuardrailResult(
            decision=Decision.MODIFY,
            reason=f"credentials redacted ({summary})",
            risk_score=60,
            modified_payload=rewrite(payload, rewritten),
            findings=findings,
            metadata=meta,
        )
