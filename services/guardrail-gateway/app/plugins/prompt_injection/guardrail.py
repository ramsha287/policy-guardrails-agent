"""`prompt-injection`: instructions hidden in user input, retrieved documents and tool results.

A fast, explainable heuristic, not a model. It looks for the well-known shapes of injected
instructions and scores each piece of text by the categories it matches:

    override          "ignore the previous instructions", "disregard your rules"
    role_spoof        fake system/assistant turns and chat-template tokens in content
    persona           "you are now ...", "from now on you will ...", "developer mode"
    exfil_directive   "send/post/forward ... to <url or address>"
    image_beacon      markdown images whose URL carries a query string
    concealment       "do not tell the user", "keep this hidden"
    hidden_text       Unicode tag characters, runs of zero-width or bidi control characters

score = 1 - prod(1 - weight) over the categories found, per text span; the request's score is the
highest span. Retrieved chunks over `escalate_at` are dropped (MODIFY) by default, so one poisoned
document doesn't stop the agent; other stages escalate; anything over `block_at` blocks.

Heuristics catch common, unsophisticated injections and miss paraphrases. Pair it with the
contextual decisions (taint labels, SENSITIVE_THEN_EXTERNAL) that don't depend on spotting the
injection at all, and roll it out in shadow mode to measure false positives on your traffic first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.plugins.common.patterns import CONFIG_SCAN_LIMIT, check_pattern
from app.plugins.common.textwalk import rewrite, walk
from guardrail_sdk import Decision, Finding, Guardrail, GuardrailResult, Payload, SecurityContext, Stage

_I = re.IGNORECASE | re.MULTILINE

CATEGORIES: dict[str, tuple[float, tuple[re.Pattern[str], ...]]] = {
    "override": (
        0.6,
        (
            re.compile(
                r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|"
                r"preceding|original|system|all)\b[^.\n]{0,20}?\b(?:instructions?|prompts?|rules|directions|"
                r"guidelines|messages|context)\b",
                _I,
            ),
        ),
    ),
    "role_spoof": (
        0.5,
        (
            re.compile(r"^[ \t]*(?:system|assistant)[ \t]*:\s", _I),
            re.compile(r"<\|(?:im_start|im_end|system|assistant|endoftext)\|>", _I),
            re.compile(r"\[/?INST\]|<</?SYS>>|</?system>", _I),
            re.compile(r"^[ \t]*#{2,}[ \t]*(?:system|new instructions?)\b", _I),
        ),
    ),
    "persona": (
        0.35,
        (
            re.compile(r"\byou are now\b", _I),
            re.compile(r"\bfrom now on,?\s+you\b", _I),
            re.compile(r"\b(?:developer|god|unrestricted|jailbreak)\s+mode\b", _I),
            re.compile(r"\bnew (?:system )?instructions?\s*:", _I),
        ),
    ),
    "exfil_directive": (
        0.45,
        (
            re.compile(
                r"\b(?:send|post|forward|upload|email|transmit|exfiltrate|leak|copy)\b[^.\n]{0,80}?\b(?:to|into)\s+"
                r"(?:https?://|[\w.+-]+@[\w-]+\.)",
                _I,
            ),
            re.compile(
                r"\b(?:append|add|include|encode)\b[^.\n]{0,60}?\b(?:to|in|into)\s+(?:the\s+)?(?:url|link|query)", _I
            ),
        ),
    ),
    "image_beacon": (0.4, (re.compile(r"!\[[^\]]{0,200}\]\([ \t]*https?://[^)\s?]{0,2048}\?[^)\s]{1,2048}\)", _I),)),
    "concealment": (
        0.3,
        (
            re.compile(
                r"\bdo not (?:tell|inform|mention|reveal|show|alert)\b[^.\n]{0,20}?\b(?:the user|anyone|them)\b", _I
            ),
            re.compile(r"\bwithout (?:telling|informing|alerting) the user\b", _I),
            re.compile(r"\bkeep this (?:secret|hidden|confidential) from\b", _I),
        ),
    ),
}
_TAGS = re.compile("[\U000e0000-\U000e007f]")
_ZERO_WIDTH = re.compile("[​‌‍⁠⁡⁢⁣⁤﻿]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
HIDDEN_WEIGHT = 0.5


@dataclass(frozen=True)
class Score:
    score: float
    categories: tuple[str, ...]


def score_text(text: str, extra: dict[str, tuple[float, tuple[re.Pattern[str], ...]]] | None = None) -> Score:
    """Built-in categories scan the whole text; config patterns (`extra`) only the first
    CONFIG_SCAN_LIMIT characters, and can add categories but never replace a built-in one."""
    found: dict[str, float] = {}
    for name, (weight, patterns) in CATEGORIES.items():
        if any(p.search(text) for p in patterns):
            found[name] = weight
    head = text[:CONFIG_SCAN_LIMIT]
    for name, (weight, patterns) in (extra or {}).items():
        if name not in found and name not in CATEGORIES and any(p.search(head) for p in patterns):
            found[name] = weight
    if _TAGS.search(text) or len(_ZERO_WIDTH.findall(text)) >= 3 or len(_BIDI.findall(text)) >= 2:
        found["hidden_text"] = HIDDEN_WEIGHT
    keep = 1.0
    for w in found.values():
        keep *= 1 - w
    return Score(round(1 - keep, 4), tuple(sorted(found)))


class ExtraPattern(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,39}$")
    pattern: str = Field(min_length=1, max_length=300)
    weight: float = Field(gt=0.0, le=1.0)

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, v: str) -> str:
        return check_pattern(v)

    @field_validator("name")
    @classmethod
    def _not_builtin(cls, v: str) -> str:
        if v in CATEGORIES or v == "hidden_text":
            raise ValueError(f"{v!r} is a built-in category; extra patterns add categories, they can't replace one")
        return v


class InjectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    escalate_at: float = Field(0.5, gt=0.0, le=1.0)
    block_at: float = Field(0.85, gt=0.0, le=1.0)
    retrieval_action: str = Field("drop_chunk", pattern=r"^(drop_chunk|escalate|block)$")
    # input/output messages to look at
    scan_roles: list[Literal["system", "user", "assistant", "tool"]] = Field(default_factory=lambda: ["user"])
    extra_patterns: list[ExtraPattern] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def _order(self) -> InjectionConfig:
        if self.block_at < self.escalate_at:
            raise ValueError("block_at must be at least escalate_at")
        names = [p.name for p in self.extra_patterns]
        if len(names) != len(set(names)):
            raise ValueError("extra pattern names must be unique")
        return self


class PromptInjectionGuardrail(Guardrail):
    config_model = InjectionConfig
    config: InjectionConfig

    async def setup(self, config: dict[str, Any]) -> None:
        await super().setup(config)
        self._extra = {p.name: (p.weight, (re.compile(p.pattern, _I),)) for p in self.config.extra_patterns}

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        c = self.config
        # Tool calls: only the result is content from elsewhere; arguments are the agent's own.
        w = walk(payload, tool_arguments=False, tool_result=True, roles=frozenset(c.scan_roles))
        findings: list[Finding] = []
        categories: set[str] = set()
        top = 0.0
        flagged_chunks: set[int] = set()  # positions in payload.chunks
        for span in w.spans:
            s = score_text(span.text, self._extra)
            if s.score <= 0:
                continue
            categories.update(s.categories)
            top = max(top, s.score)
            if s.score < c.escalate_at:
                continue  # a weak signal: in metadata (score, categories), not a finding
            findings.append(Finding(type="PROMPT_INJECTION", score=s.score, location=span.location))
            if span.key[:1] == ("chunks",):
                flagged_chunks.add(span.key[1])
        meta: dict[str, object] = {"categories": sorted(categories), "score": top}
        if w.truncated:
            meta["truncated"] = True
        risk = int(top * 100)
        if top < c.escalate_at:
            return GuardrailResult(
                decision=Decision.ALLOW,
                reason="weak injection signals only" if categories else "no injection signals",
                risk_score=risk,
                findings=findings,
                metadata=meta,
            )
        what = ", ".join(sorted(categories))
        if top >= c.block_at:
            return GuardrailResult(
                decision=Decision.BLOCK,
                reason=f"prompt injection ({what})",
                risk_score=risk,
                findings=findings,
                metadata=meta,
            )
        if payload.stage == Stage.RETRIEVAL and c.retrieval_action == "drop_chunk" and flagged_chunks:
            meta["dropped_chunks"] = len(flagged_chunks)
            return GuardrailResult(
                decision=Decision.MODIFY,
                reason=f"dropped {len(flagged_chunks)} chunk(s) with injected instructions ({what})",
                risk_score=risk,
                modified_payload=rewrite(payload, {}, drop_chunks=frozenset(flagged_chunks)),
                findings=findings,
                metadata=meta,
            )
        if payload.stage == Stage.RETRIEVAL and c.retrieval_action == "block":
            return GuardrailResult(
                decision=Decision.BLOCK,
                reason=f"prompt injection ({what})",
                risk_score=risk,
                findings=findings,
                metadata=meta,
            )
        return GuardrailResult(
            decision=Decision.ESCALATE,
            reason=f"possible prompt injection ({what})",
            risk_score=risk,
            findings=findings,
            metadata=meta,
        )
