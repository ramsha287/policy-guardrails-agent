# Authorization policy for the guardrail gateway.
#
# OPA decides WHETHER an agent may do something at all; guardrails decide whether the
# content is safe. Entry point: data.guardrails.authz.decision
#
# input = {
#   "stage": "input" | "retrieval" | "tool" | "output" | "agent",
#   "context": SecurityContext (without arguments),
#   "agent": {"known": bool, "allowed_tools": [string]},
#   "action_known": bool,
#   "tool_name": string | null
# }
package guardrails.authz

import rego.v1

# Starter thresholds. Tune per environment.
min_trust_production := 50

max_risk_production := 70

max_delegation_depth := 3

default allow := false

allow if count(deny_reasons) == 0

deny_reasons contains msg if {
	input.context.environment == "production"
	input.context.trust_score < min_trust_production
	msg := sprintf("agent trust %d is below %d in production", [input.context.trust_score, min_trust_production])
}

deny_reasons contains msg if {
	input.context.environment == "production"
	input.context.risk_score > max_risk_production
	msg := sprintf("action risk %d is above %d in production", [input.context.risk_score, max_risk_production])
}

deny_reasons contains msg if {
	count(input.context.delegation_chain) > max_delegation_depth
	msg := sprintf("delegation chain depth %d exceeds %d", [count(input.context.delegation_chain), max_delegation_depth])
}

deny_reasons contains msg if {
	input.stage == "tool"
	not tool_allowed
	msg := sprintf("tool %q is not in the agent's allowed tools", [input.tool_name])
}

tool_allowed if "*" in input.agent.allowed_tools

tool_allowed if input.tool_name in input.agent.allowed_tools

# Obligations: guardrails that MUST run for this request. The engine blocks the request
# if an obligated guardrail is not assigned for the stage.
obligations contains "ai-gateway-pii" if {
	input.context.data_classification in {"PII", "CONFIDENTIAL"}
	input.stage in {"input", "retrieval", "tool", "output"}
}

reason := "allowed" if allow

reason := concat("; ", sort(deny_reasons)) if not allow

decision := {
	"allow": allow,
	"reason": reason,
	"obligations": sort(obligations),
}
