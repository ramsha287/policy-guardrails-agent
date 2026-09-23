"""Wire schemas for the gateway's /v1/guard/{stage} API (shared by the gateway and the agent client)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .models import Chunk, DataClassification, Decision, Finding, Message, Stage, ToolCall


class GuardPayloadIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str | None = None
    messages: list[Message] | None = None
    chunks: list[Chunk] | None = None
    tool_call: ToolCall | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)


class GuardRequest(BaseModel):
    """Body of POST /v1/guard/{stage}. Tenant and environment come from the API key and gateway config."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=128, examples=["llm.chat", "database.read"])
    resource: str | None = Field(default=None, max_length=256)
    user_id: str | None = Field(default=None, max_length=128)
    session_id: str | None = Field(default=None, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    data_classification: DataClassification = "INTERNAL"
    delegation_chain: list[str] = Field(default_factory=list, max_length=16)
    tool_metadata: dict[str, Any] | None = None
    payload: GuardPayloadIn


class GuardrailOutcome(BaseModel):
    guardrail_id: str
    version: str
    decision: Decision
    reason: str
    risk_score: int
    latency_ms: float
    mode: str  # enforce | shadow
    error: str | None = None
    findings: list[Finding] = Field(default_factory=list)


class PolicyOutcome(BaseModel):
    allow: bool
    reason: str
    obligations: list[str] = Field(default_factory=list)


class GuardResponse(BaseModel):
    request_id: str
    trace_id: str
    stage: Stage
    decision: Decision
    reason: str
    risk_score: int
    trust_score: int
    payload: GuardPayloadIn | None  # safe payload to use; None when blocked
    policy: PolicyOutcome
    results: list[GuardrailOutcome] = Field(default_factory=list)
    snapshot_version: str | None = None
    # Set when decision == "escalate" (HTTP 202): poll GET /v1/escalations/{escalation_id}.
    escalation_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.MODIFY)
