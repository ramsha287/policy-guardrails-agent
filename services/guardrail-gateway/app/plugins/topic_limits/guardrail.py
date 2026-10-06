"""`topic-limits`: keep an agent to what it is for.

Two lists, both optional, set per assignment (so per tenant or agent):

- `denied_topics`: subjects the agent must not handle (e.g. legal advice for a support bot). A
  message that matches one is blocked or escalated.
- `allowed_topics`: what the agent is for. When set, a message that matches none of them is out of
  scope (escalated by default). Short messages ("hi", "thanks") are never out of scope.

A topic is a name plus keywords (whole words or phrases, case-insensitive) and/or regular
expressions. Matching is deterministic and in process. Findings name the topic, never the text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.plugins.common.patterns import CONFIG_SCAN_LIMIT, check_pattern
from app.plugins.common.textwalk import walk
from guardrail_sdk import Decision, Finding, Guardrail, GuardrailResult, Payload, SecurityContext

_WORD = re.compile(r"[\w']+")


class Topic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    keywords: list[str] = Field(default_factory=list, max_length=500)
    patterns: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("keywords")
    @classmethod
    def _keywords(cls, v: list[str]) -> list[str]:
        out = [k.strip().lower() for k in v if k.strip()]
        if any(len(k) > 100 for k in out):
            raise ValueError("keywords are at most 100 characters")
        return out

    @field_validator("patterns")
    @classmethod
    def _patterns(cls, v: list[str]) -> list[str]:
        return [check_pattern(p) for p in v]

    @model_validator(mode="after")
    def _something(self) -> Topic:
        if not self.keywords and not self.patterns:
            raise ValueError(f"topic {self.name!r} needs keywords or patterns")
        return self

    def matcher(self) -> TopicMatcher:
        """Keywords become one escaped alternation; each config pattern is compiled on its own (so
        groups and flags can't collide) and only sees the first CONFIG_SCAN_LIMIT characters."""
        words = [r"(?<![\w'])" + r"\s+".join(map(re.escape, k.split())) + r"(?![\w'])" for k in self.keywords]
        return TopicMatcher(
            re.compile("|".join(words), re.IGNORECASE) if words else None,
            tuple(re.compile(p, re.IGNORECASE) for p in self.patterns),
        )


@dataclass(frozen=True)
class TopicMatcher:
    keywords: re.Pattern[str] | None
    patterns: tuple[re.Pattern[str], ...]

    def search(self, text: str) -> bool:
        if self.keywords is not None and self.keywords.search(text):
            return True
        head = text[:CONFIG_SCAN_LIMIT]
        return any(p.search(head) for p in self.patterns)


class TopicConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    denied_topics: list[Topic] = Field(default_factory=list, max_length=100)
    allowed_topics: list[Topic] = Field(default_factory=list, max_length=100)
    on_denied: Literal["block", "escalate"] = "block"
    on_out_of_scope: Literal["block", "escalate", "allow"] = "escalate"
    min_words_for_scope: int = Field(4, ge=1, le=100)
    scan_roles: list[Literal["system", "user", "assistant", "tool"]] = Field(default_factory=lambda: ["user"])

    @model_validator(mode="after")
    def _non_empty(self) -> TopicConfig:
        if not self.denied_topics and not self.allowed_topics:
            raise ValueError("configure denied_topics, allowed_topics or both")
        names = [t.name for t in (*self.denied_topics, *self.allowed_topics)]
        if len(names) != len(set(names)):
            raise ValueError("topic names must be unique")
        return self


class TopicLimitsGuardrail(Guardrail):
    config_model = TopicConfig
    config: TopicConfig

    async def setup(self, config: dict[str, Any]) -> None:
        await super().setup(config)
        self._denied = [(t.name, t.matcher()) for t in self.config.denied_topics]
        self._allowed = [(t.name, t.matcher()) for t in self.config.allowed_topics]

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        c = self.config
        w = walk(payload, roles=frozenset(c.scan_roles), tool_arguments=False, tool_result=False)
        denied: dict[str, str] = {}  # topic -> first location
        words = 0
        in_scope = False
        for span in w.spans:
            words += len(_WORD.findall(span.text))
            for name, rx in self._denied:
                if name not in denied and rx.search(span.text):
                    denied[name] = span.location
            if not in_scope and any(rx.search(span.text) for _, rx in self._allowed):
                in_scope = True
        if denied:
            names = sorted(denied)
            findings = [Finding(type="DENIED_TOPIC", location=denied[n]) for n in names]
            decision = Decision.BLOCK if c.on_denied == "block" else Decision.ESCALATE
            return GuardrailResult(
                decision=decision,
                reason=f"denied topic: {', '.join(names)}",
                risk_score=70,
                findings=findings,
                metadata={"topics": names},
            )
        if self._allowed and not in_scope and words >= c.min_words_for_scope and c.on_out_of_scope != "allow":
            decision = Decision.BLOCK if c.on_out_of_scope == "block" else Decision.ESCALATE
            return GuardrailResult(
                decision=decision,
                reason="outside the agent's allowed topics",
                risk_score=40,
                findings=[Finding(type="OUT_OF_SCOPE")],
                metadata={"allowed": [n for n, _ in self._allowed]},
            )
        return GuardrailResult(decision=Decision.ALLOW, reason="within topic limits")
