"""Deterministic rules: is it an agent, what state is it in, and which findings does that open?

Every result carries the reasons behind it, in words an operator can check against the evidence.
No model is asked anything.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from ..domain.inventory import STALE_AFTER_DAYS, EntityRecord

# Kinds that can be agents. Tools, data stores, providers and credentials never are.
AGENT_CAPABLE = frozenset({"agent", "workload", "endpoint", "identity"})
AUTO_FINDINGS = frozenset({"shadow_agent", "probable_shadow_agent", "unmanaged_agent", "stale_agent"})
REGISTRY_SOURCE = "registry"


def classify(kind: str, signals: set[str]) -> tuple[str, list[str]]:
    """-> (confirmed | probable | none, reasons)."""
    if kind not in AGENT_CAPABLE:
        return "none", []
    if "human_identity" in signals:
        return "none", ["a person's identity"]
    if "registered" in signals:
        return "confirmed", ["registered in the agent registry"]
    if "agent_runtime" in signals:
        return "confirmed", ["a managed agent runtime reports it as an agent"]
    if "gateway_client" in signals and kind == "agent":
        return "confirmed", ["calls the guardrail gateway as an agent"]
    if "llm_server" in signals and "calls_model" not in signals:
        return "none", ["serves a model (LLM server)"]
    tools = "uses_tools" in signals or "mcp_client" in signals
    if "calls_model" in signals and tools:
        return "confirmed", ["calls a model and uses tools or data"]
    if "calls_model" in signals and "agent_framework" in signals:
        return "confirmed", ["calls a model with an agent framework"]
    if "agent_framework" in signals:
        return "probable", ["runs an agent framework"]
    if "mcp_client" in signals:
        return "probable", ["is an MCP client"]
    if "calls_model" in signals:
        return "probable", ["calls a model; no tool or data use seen yet"]
    return "none", []


def state_of(entity: EntityRecord, signals: set[str], observed: bool, now: datetime) -> tuple[str, list[str]]:
    """Reconciliation against the registry. `observed` = some source other than the registry has it."""
    if entity.agent_likelihood == "none":
        return "not_agent", []
    stale_before = now - timedelta(days=STALE_AFTER_DAYS)
    if entity.registry_agent_id:
        if not observed:
            if entity.first_seen < stale_before:
                return "stale", [f"registered, not observed by any connector for {STALE_AFTER_DAYS} days"]
            return "registered_unmanaged", ["registered; not observed by any connector yet"]
        if entity.last_seen < stale_before:
            return "stale", [f"registered, last observed {entity.last_seen.date().isoformat()}"]
        if "direct_model_access" in signals:
            return "registered_unmanaged", ["registered, but calls a model provider without the gateway"]
        if "gateway_client" in signals:
            return "managed", ["registered and calling through the guardrail gateway"]
        return "registered_unmanaged", ["registered, but never seen calling through the gateway"]
    if "gateway_client" in signals and entity.kind == "agent":
        return "shadow", ["calls the gateway with an agent_id that is not in the registry"]
    return "shadow", ["agent-like behaviour with no registry entry"]


def wanted_findings(entity: EntityRecord, observed: bool, now: datetime) -> dict[str, tuple[str, str]]:
    """Automatic findings this entity should have open: kind -> (severity, summary)."""
    if entity.ignored(now):
        return {}
    if entity.state == "stale":
        return {
            "stale_agent": ("low", f"Registered agent {entity.registry_agent_id} not seen for {STALE_AFTER_DAYS} days")
        }
    if not observed or entity.last_seen < now - timedelta(days=STALE_AFTER_DAYS):
        return {}
    prod = entity.environment == "production"
    where = f" in {entity.environment}" if entity.environment else ""
    if entity.state == "shadow":
        if entity.agent_likelihood == "confirmed":
            return {"shadow_agent": ("high" if prod else "medium", f"Unregistered agent {entity.name}{where}")}
        return {
            "probable_shadow_agent": ("medium" if prod else "low", f"Possible unregistered agent {entity.name}{where}")
        }
    if entity.state == "registered_unmanaged":
        how = (
            "calls models around the gateway"
            if "without the gateway" in " ".join(entity.reasons)
            else "is not seen at the gateway"
        )
        return {"unmanaged_agent": ("medium", f"Registered agent {entity.registry_agent_id} {how}{where}")}
    return {}
