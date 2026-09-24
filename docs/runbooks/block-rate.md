# GuardrailBlockRateSpike

**What it means.** More than 20% of guard requests are blocked. Either something is attacking an
agent, or a change is blocking legitimate traffic.

**Triage in the console**

1. **Analytics**: which stage and which guardrail are blocking? Is it one tenant (filter by tenant)?
2. **Activity log**: was anything published or changed just before the spike? (snapshot,
   assignment, agent, action, modifier)
3. **Simulate** a representative request against the live pipeline to see each guardrail's decision.

**If it's a bad change**: roll back (Pipeline → Published versions). In production that needs a
second admin. For a new guardrail, put it back to `shadow` and compare shadow decisions for a
while before enforcing again.

**If it's policy (OPA) denials** (`opa_deny_total`): usually an agent without a profile (trust 0), an
action missing from the catalog (risk 100), or a tool not on the agent's list. Fix the catalog
in Tenants & keys.

**If it's an attack**: keep blocking. Find the API key in the audit log (the `tenant_id` and
`agent_id` columns), then revoke the key or suspend the tenant in the console.
