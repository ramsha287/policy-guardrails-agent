"""Public contracts shared by the gateway, the control plane and every guardrail plugin.

Changing a field here is a contract change: bump the SDK minor version for
additive changes and the major version for breaking ones.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SDK_VERSION = "1.0.0"


class Stage(str, Enum):
    INPUT = "input"
    RETRIEVAL = "retrieval"
    TOOL = "tool"
    OUTPUT = "output"
    AGENT = "agent"


class Decision(str, Enum):
    ALLOW = "allow"
    MODIFY = "modify"
    ESCALATE = "escalate"
    BLOCK = "block"


# Strongest decision wins: BLOCK > ESCALATE > MODIFY > ALLOW
DECISION_PRECEDENCE: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.MODIFY: 1,
    Decision.ESCALATE: 2,
    Decision.BLOCK: 3,
}

DataClassification = Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII"]
Environment = Literal["dev", "staging", "production"]


class SecurityContext(BaseModel):
    """Who is asking to do what. Built by the Context Builder; read-only for guardrails."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    trace_id: str
    tenant_id: str
    agent_id: str
    user_id: str | None = None
    session_id: str | None = None
    action: str
    resource: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    trust_score: int = Field(ge=0, le=100)
    risk_score: int = Field(ge=0, le=100)
    data_classification: DataClassification = "INTERNAL"
    environment: Environment
    delegation_chain: list[str] = Field(default_factory=list)
    tool_metadata: dict[str, Any] | None = None


class Chunk(BaseModel):
    """A retrieved document chunk (retrieval stage)."""

    id: str
    text: str
    source: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """A tool invocation (tool stage). `result` is set when guarding the tool's output."""

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any | None = None


class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str


class Payload(BaseModel):
    """What a stage inspects. Typed fields per stage plus `extensions` for future guardrails."""

    stage: Stage
    text: str | None = None
    messages: list[Message] | None = None
    chunks: list[Chunk] | None = None
    tool_call: ToolCall | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _has_content_for_stage(self) -> Payload:
        if self.stage in (Stage.INPUT, Stage.OUTPUT):
            if self.text is None and not self.messages:
                raise ValueError(f"{self.stage.value} payload needs `text` or `messages`")
        elif self.stage == Stage.RETRIEVAL:
            if self.chunks is None:
                raise ValueError("retrieval payload needs `chunks`")
        elif self.stage == Stage.TOOL:
            if self.tool_call is None:
                raise ValueError("tool payload needs `tool_call`")
        return self

    def same_shape_as(self, other: Payload) -> bool:
        """True when `other` (a modified copy) keeps this payload's shape (requirement B2).

        Call it on the original: ``original.same_shape_as(modified)``.
        """
        if self.stage != other.stage:
            return False
        if (self.text is None) != (other.text is None):
            return False
        if (self.messages is None) != (other.messages is None):
            return False
        if self.messages is not None and other.messages is not None:
            if [m.role for m in self.messages] != [m.role for m in other.messages]:
                return False
        if (self.chunks is None) != (other.chunks is None):
            return False
        if self.chunks is not None and other.chunks is not None:
            # Chunks may be dropped, never invented or re-labelled.
            if not {c.id for c in other.chunks} <= {c.id for c in self.chunks}:
                return False
        if (self.tool_call is None) != (other.tool_call is None):
            return False
        if self.tool_call is not None and other.tool_call is not None:
            if self.tool_call.name != other.tool_call.name:
                return False
        return True


class Finding(BaseModel):
    """What a guardrail detected. Never carries the raw sensitive value (requirement C3)."""

    type: str
    score: float = Field(ge=0.0, le=1.0, default=1.0)
    start: int | None = None
    end: int | None = None
    location: str | None = None  # e.g. "text", "messages[2]", "chunks[c-7]", "tool_call.arguments.email"


class GuardrailResult(BaseModel):
    decision: Decision
    reason: str
    risk_score: int = Field(ge=0, le=100, default=0)
    modified_payload: Payload | None = None
    findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = 0.0

    @model_validator(mode="after")
    def _modify_needs_payload(self) -> GuardrailResult:
        if self.decision == Decision.MODIFY and self.modified_payload is None:
            raise ValueError("MODIFY requires `modified_payload`")
        if not self.reason.strip():
            raise ValueError("`reason` must be a human-readable explanation")
        return self


def strongest(decisions: list[Decision]) -> Decision:
    if not decisions:
        return Decision.ALLOW
    return max(decisions, key=lambda d: DECISION_PRECEDENCE[d])
