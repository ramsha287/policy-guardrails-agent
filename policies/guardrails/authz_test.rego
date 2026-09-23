package guardrails.authz_test

import data.guardrails.authz
import rego.v1

base_context := {
	"request_id": "req-001",
	"trace_id": "0af7651916cd43dd8448eb211c80319c",
	"tenant_id": "demo",
	"agent_id": "research-agent",
	"action": "database.read",
	"resource": "customer_db",
	"trust_score": 82,
	"risk_score": 20,
	"data_classification": "INTERNAL",
	"environment": "production",
	"delegation_chain": [],
}

mk(overrides) := object.union(
	{
		"stage": "input",
		"context": base_context,
		"agent": {"known": true, "allowed_tools": ["*"]},
		"action_known": true,
		"tool_name": null,
	},
	overrides,
)

test_allows_trusted_low_risk if {
	d := authz.decision with input as mk({})
	d.allow
	d.reason == "allowed"
	d.obligations == []
}

test_denies_low_trust_in_production if {
	ctx := object.union(base_context, {"trust_score": 10})
	d := authz.decision with input as mk({"context": ctx})
	not d.allow
	contains(d.reason, "trust 10")
}

test_low_trust_allowed_in_dev if {
	ctx := object.union(base_context, {"trust_score": 0, "environment": "dev"})
	d := authz.decision with input as mk({"context": ctx})
	d.allow
}

test_denies_high_risk_in_production if {
	ctx := object.union(base_context, {"risk_score": 100})
	d := authz.decision with input as mk({"context": ctx})
	not d.allow
	contains(d.reason, "risk 100")
}

test_denies_deep_delegation if {
	ctx := object.union(base_context, {"delegation_chain": ["a", "b", "c", "d"], "environment": "dev"})
	d := authz.decision with input as mk({"context": ctx})
	not d.allow
}

test_denies_unlisted_tool if {
	d := authz.decision with input as mk({
		"stage": "tool",
		"tool_name": "shell.exec",
		"agent": {"known": true, "allowed_tools": ["database.read"]},
	})
	not d.allow
	contains(d.reason, "shell.exec")
}

test_allows_listed_tool if {
	d := authz.decision with input as mk({
		"stage": "tool",
		"tool_name": "database.read",
		"agent": {"known": true, "allowed_tools": ["database.read"]},
	})
	d.allow
}

test_pii_obligates_ai_gateway_on_input if {
	ctx := object.union(base_context, {"data_classification": "PII"})
	d := authz.decision with input as mk({"context": ctx})
	d.obligations == ["ai-gateway-pii"]
}

test_pii_obligates_ai_gateway_on_retrieval_and_tool if {
	ctx := object.union(base_context, {"data_classification": "PII"})
	d1 := authz.decision with input as mk({"context": ctx, "stage": "retrieval"})
	d1.obligations == ["ai-gateway-pii"]
	d2 := authz.decision with input as mk({"context": ctx, "stage": "tool", "tool_name": "database.read"})
	d2.obligations == ["ai-gateway-pii"]
}

test_no_obligation_on_agent_stage if {
	ctx := object.union(base_context, {"data_classification": "PII"})
	d := authz.decision with input as mk({"context": ctx, "stage": "agent"})
	d.obligations == []
}

test_no_obligation_for_internal_data if {
	d := authz.decision with input as mk({"stage": "retrieval"})
	d.obligations == []
}
