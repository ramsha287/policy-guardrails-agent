# Testing contextual decisions (sprints A and B)

How to check that identity binding, risk, verification, the AuthZEN API and decision events
work. Part 1 needs only Python. Part 2 runs against the Docker Compose stack and takes about 20
minutes. Each check lists what you should see, and the troubleshooting table at the end covers
what to do when you don't.

## Part 1: automated tests (no stack needed)

```bash
# Gateway (needs Postgres only for tests/integration; those skip without POSTGRES_TEST_DSN)
cd services/guardrail-gateway && pip install -r requirements-dev.txt
pytest -q

# SDK
cd packages/guardrail-sdk && pip install -e ".[test]" && pytest -q
```

| Test file | What it proves |
| --- | --- |
| `tests/test_contextual_flow.py` | Bound keys can't act as another agent; shadow changes nothing; enforce holds, blocks and quarantines |
| `tests/test_verify.py` | The assurance model, the planner, both verification stores (memory and Redis), IdP tokens (wrong user, old sign-in, wrong issuer/audience/key, `acr`, nonce, no HS256 algorithm confusion, JWKS with encryption keys), dry run, evidence used once (also under concurrent retries) and bound to one request |
| `tests/test_verification_flow.py` | The full flow: a dry run turns a high-risk read into `allow`; a user confirmation round trip; a "no" denies the retry; a changed payload or `arguments` needs a new confirmation; shadow runs nothing |
| `tests/test_authzen.py`, `tests/test_api.py` | AuthZEN mapping and HTTP endpoints; the verification routes (401/403/404/409) |
| `tests/test_outbox.py` | Event envelopes carry no free text; webhook signatures; Redis channels |
| `tests/integration/test_postgres.py` | With `POSTGRES_TEST_DSN`: outbox rows are written in the audit transaction, a failing sink loses nothing, chain heads are exported, old rows are pruned |

All green means the logic is right. Part 2 checks your deployment and wiring.

## Part 2: the live stack

### Setup

```bash
docker compose up --build -d
until curl -sf localhost:8100/ready >/dev/null; do sleep 5; done

ADMIN=$(docker compose exec -T guardrail-control-plane sh -c '. /bootstrap/cp.env; echo $CP_ADMIN_KEY')
cpapi() { curl -s "localhost:8200/cp/v1$1" -H "X-Admin-Key: $ADMIN" -H 'Content-Type: application/json' "${@:2}"; }

# A key bound to research-agent (identity assurance A1)
KEY=$(cpapi /tenants/demo/api-keys -X POST -d '{"name": "research-agent-test", "agent_id": "research-agent"}' | jq -r .key)
# The demo catalog has no http.post action yet; unknown actions are scored as high risk (fail closed)
cpapi /tenants/demo/actions -X PUT -d '{"action": "http.post", "resource_pattern": "*", "base_risk_score": 30}'
sleep 35   # the gateway polls the control plane every 30 s

tool() { curl -s -w '\n' localhost:8100/v1/guard/tool -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d "$1"; }
RUN=$(date +%s)
# An external send. Each check uses its own host and session: once a send to a host is allowed,
# the agent "knows" that host for 90 days and the same request is no longer risky enough to verify.
post() { echo '{"agent_id": "research-agent", "action": "http.post", "user_id": "u1", "session_id": "s-'$RUN-$1'",
  '"$2"' "payload": {"tool_call": {"name": "http.post",
  "arguments": {"url": "https://paste-'$RUN-$1'.example.org/upload", "body": "quarterly numbers"}}}}'; }
CHANNEL='"verification_channels": ["user_confirmation"],'
```

### Check 1: identity binding (always enforced)

```bash
tool '{"agent_id": "admin-agent", "action": "llm.chat", "payload": {"tool_call": {"name": "x", "arguments": {}}}}' \
  | jq '{decision, outcome, reason_codes}'
```

Expect `"decision": "block"`, `"outcome": "deny"`, `"reason_codes": ["KEY_AGENT_MISMATCH"]` (HTTP 403).
The key belongs to research-agent, so it can't claim to be anyone else.

### Check 2: shadow mode computes and changes nothing

The stack starts in shadow mode (`RISK_MODE=shadow`).

```bash
tool "$(post a "$CHANNEL")" | jq '{decision, outcome, mode: .risk.mode, band: .risk.band, would: .risk.would_outcome}'
```

Expect `decision: "allow"`, `mode: "shadow"`, `band: "elevated"`, `would: "verify"`. The request
went through, and `would` shows what enforce mode will do: ask the user.

### Check 3: user confirmation (enforce mode)

```bash
RISK_MODE=enforce docker compose up -d guardrail-gateway
until curl -sf localhost:8100/ready >/dev/null; do sleep 2; done

POST=$(post b "$CHANNEL")
tool "$POST" | tee /tmp/first.json | jq '{decision, outcome, escalation_id, reason_codes, verification}'
VID=$(jq -r .verification.id /tmp/first.json)
```

Expect HTTP 202 with `outcome: "verify"`, `decision: "escalate"`, `escalation_id: null` (no
reviewer is involved), and a `verification` with `status: "pending"` and a `summary` like
"research-agent wants to send data to paste-….example.org (external destination)". This is what
your app shows the user.

Now play the user. In production your app signs the user in again with `nonce` set to the
verification id and sends that token; the dev stack accepts tokens minted with the dev secret:

```bash
mint() { docker compose exec -T guardrail-gateway python -m app.cli dev-user-token --user "$1" ${2:+--verification "$2"}; }
USER_TOKEN=$(mint u1 "$VID")
OTHER_TOKEN=$(mint u2 "$VID")
PLAIN_TOKEN=$(mint u1)        # u1, but not issued for this confirmation (no nonce)
confirm() { curl -s -w ' HTTP %{http_code}\n' localhost:8100/v1/verifications/$VID/confirm \
  -H "X-API-Key: $KEY" -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -d "{\"approve\": $2}"; }

confirm "$OTHER_TOKEN" true     # expect HTTP 403: token belongs to a different user
confirm "$PLAIN_TOKEN" true     # expect HTTP 403: not issued for this confirmation (nonce)
confirm "$USER_TOKEN" true      # expect HTTP 200, "status": "confirmed"
confirm "$USER_TOKEN" true      # expect HTTP 409: already confirmed
tool "$POST" | jq '{decision, outcome, reason_codes}'       # the agent retries the identical request
```

The retry returns `decision: "allow"` and `reason_codes` containing `VERIFIED` and
`EVIDENCE_USER_CONFIRMATION`. (The confirmation was for this exact request: a different body,
user or session needs its own. The automated tests check that, and that evidence works once.)

**The "no" path:**

```bash
POST=$(post c "$CHANNEL"); VID=$(tool "$POST" | jq -r .verification.id)
confirm "$(mint u1 "$VID")" false
tool "$POST" | jq '{decision, outcome, reason_codes}'
```

Expect `decision: "block"`, `outcome: "deny"` and `USER_REJECTED` (HTTP 403).

**The "no channel" path:** `tool "$(post d '')" | jq '{outcome, escalation_id, reason_codes}'`.
Expect HTTP 202 with `outcome: "hold"`, `VERIFY_NEEDS_HUMAN` and an `escalation_id`: the request is
in the console's review queue, as before sprint B.

### Check 4: SQL dry run

Create a table to stand in for a read replica, then point the dry run at it:

```bash
docker compose exec -T postgres psql -U gateway -d gateway -c "
  CREATE TABLE public.customers_$RUN AS
    SELECT g AS id, 'c' || g AS name, 'pro' AS plan, CASE WHEN g % 2 = 0 THEN 'EU' ELSE 'US' END AS region
    FROM generate_series(1, 100000) g;
  ANALYZE public.customers_$RUN;"

RISK_MODE=enforce VERIFY_SQL_DRY_RUN='{"database.read": "postgresql://gateway:gateway@postgres:5432/gateway"}' \
  docker compose up -d guardrail-gateway
until curl -sf localhost:8100/ready >/dev/null; do sleep 2; done

READ='{"agent_id": "research-agent", "action": "database.read", "resource": "customer_db", "session_id": "s-'$RUN'-sql",
  "data_classification": "CONFIDENTIAL",
  "payload": {"tool_call": {"name": "database.read", "arguments": {"sql": "SELECT name, plan FROM customers_'$RUN' WHERE region = '"'EU'"' LIMIT 200"}}}}'
tool "$READ" | jq '{decision, outcome, band: .risk.band, reason_codes}'
```

Expect `band: "high"`, `decision: "allow"`, and `reason_codes` containing `RISK_HIGH`, `VERIFIED`
and `EVIDENCE_DRY_RUN`. The gateway asked Postgres's planner (`EXPLAIN`, never executed) how many
rows this would return, got about 200, and let it through without anyone being asked.

To see the hold path, lower the limit and use a fresh table name (the agent has now seen this one):

```bash
RISK_MODE=enforce VERIFY_DRY_RUN_MAX_ROWS=100 \
  VERIFY_SQL_DRY_RUN='{"database.read": "postgresql://gateway:gateway@postgres:5432/gateway"}' \
  docker compose up -d guardrail-gateway
# create customers_${RUN}b as above, send the same request against it
```

Expect HTTP 202, `outcome: "hold"` and `DRY_RUN_TOO_MANY_ROWS`. A table that doesn't exist on the
replica gives `DRY_RUN_FAILED`, also a hold. A failed dry run never allows anything.

### Check 5: AuthZEN

```bash
curl -s localhost:8100/.well-known/authzen-configuration | jq
curl -s localhost:8100/access/v1/evaluation -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{
  "subject": {"type": "agent", "id": "research-agent", "properties": {"session_id": "s-'$RUN'-e"}},
  "action": {"name": "llm.chat"},
  "resource": {"type": "model", "id": "gpt", "properties": {"arguments": {"prompt": "hello"}}}}' | jq
```

Expect `"decision": true` and `context.outcome: "allow"` with a `decision_id`. An external send
(action `http.post`, arguments under `resource.properties.arguments`, a new host) gives
`"decision": false` with `context.outcome: "hold"`, or `"verify"` and `context.verification` when
you add `"context": {"verification_channels": ["user_confirmation"]}` and a `user_id` in
`subject.properties`. A batch:

```bash
curl -s localhost:8100/access/v1/evaluations -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{
  "subject": {"type": "agent", "id": "research-agent"}, "action": {"name": "llm.chat"},
  "evaluations": [{"resource": {"id": "a"}}, {"subject": {"type": "agent", "id": "admin-agent"}}, {"resource": {"id": "c"}}],
  "options": {"evaluations_semantic": "deny_on_first_deny"}}' | jq '[.evaluations[].decision]'
```

Expect `[true, false]`: the second item is denied (`KEY_AGENT_MISMATCH`) and the batch stops there.

### Check 6: decision events

The compose stack sets `OUTBOX_SINKS=redis`. In a second terminal:

```bash
docker compose exec redis redis-cli PSUBSCRIBE 'events.*'
```

Send any request (for example check 5 again). Within about two seconds you see a message on
`events.decision.made.v1`: a CloudEvent with `type: "io.guardrail.decision.made.v1"`, the
`tenantid`, and `data` with the outcome, reason codes, risk band and `record_hash`, but no prompt
or arguments. In the database:

```bash
docker compose exec -T postgres psql -U gateway -d gateway -c \
  "SELECT topic, count(*), count(published_at) AS published FROM guardrail.outbox GROUP BY 1;"
curl -s localhost:8100/metrics | grep -E '^guardrail_outbox_(published_total|backlog|errors_total)'
```

`published` should equal `count`, and `guardrail_outbox_backlog` (refreshed every minute) should
be 0. To see that nothing is lost when a sink is down, stop Redis (`docker compose stop redis`),
send a few requests, and run the SQL again: `count` grows, `published` doesn't, and
`guardrail_outbox_errors_total{sink="redis"}` counts up. Start Redis again and within a few
seconds `published` catches up. (While Redis is down, session state is unavailable too, so
decisions are stricter and `/ready` reports Redis as down. That is expected.)

`audit.chain_heads.v1` events arrive hourly and when a gateway stops (`docker compose restart
guardrail-gateway` shows one per tenant on `events.audit.chain_heads.v1`).

### Check 7: the audit chain

```bash
docker compose exec -T guardrail-gateway python -m app.cli verify-audit-chain --days 1
```

Expect exit code 0 and a summary with no problems. Then compare the newest
`audit.chain_heads.v1` event (from Redis, or `SELECT payload->'data' FROM guardrail.outbox WHERE
topic = 'audit.chain_heads.v1' ORDER BY id DESC LIMIT 1`) with the database:

```bash
docker compose exec -T postgres psql -U gateway -d gateway -c \
  "SELECT chain_id, tenant_id, max(chain_seq) FROM audit.audit_events GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 5;"
```

For the exported `chain_id` and tenant, the row with that `chain_seq` must have the exported
`record_hash`. If someone rewrote the audit table, it won't.

## What "working" looks like

| Check | Pass when |
| --- | --- |
| Identity | Mismatched `agent_id` → 403 `KEY_AGENT_MISMATCH` |
| Shadow | Decisions unchanged, `risk.would_outcome` filled in |
| User confirmation | 202 `verify` → wrong user 403 → right user 200 → retry `allow` → next identical request asks again |
| Dry run | Small read on a high-risk path → `allow` with `EVIDENCE_DRY_RUN`; big or failing → `hold` |
| AuthZEN | `decision` true/false matches `/v1/guard/tool`; batch semantics respected |
| Events | One `decision.made.v1` per audit row; backlog 0; survives a sink outage |
| Audit chain | `verify-audit-chain` exits 0; heads match the exported events |

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Every `http.post` is `critical` | The action isn't in the catalog (unknown actions start high), or the 30 s catalog poll hasn't happened yet |
| Check 3 gives `hold` + `VERIFY_NEEDS_HUMAN` | No `user_id`, no `verification_channels`, or the gateway has neither `VERIFY_OIDC_*` nor `VERIFY_DEV_SECRET`. The startup log line "contextual decisions: … verification=…" lists what is enabled |
| Check 3 gives `allow` straight away | The host was already used by this agent (no `NEW_RESOURCE`, so the band is low). Use a new suffix or a new `RUN=$(date +%s)` |
| Confirm returns 403 "sign in again" | The token is older than `VERIFY_MAX_AUTH_AGE_SECONDS` (10 min); mint a new one |
| Confirm returns 404 | Different tenant key, the verification expired (10 min), or (without Redis) another gateway replica created it |
| Retry is `verify` again after confirming | The retry isn't byte-for-byte the same request (body, user, session, resource), or the evidence was already used |
| Dry run gives `DRY_RUN_FAILED` | The table doesn't exist on the dry-run database, the DSN is wrong (it must be `postgresql://…`, not `postgresql+asyncpg://…`) or it timed out (2 s) |
| No events on Redis | `OUTBOX_SINKS` empty, or you subscribed after the event was published (pub/sub doesn't replay); check `guardrail.outbox` |
| Gateway won't start: `VERIFY_DEV_SECRET` | It's set with `GATEWAY_ENV` other than `dev` (refused) or is shorter than 32 characters |
| Confirm returns 403 "nonce" | The token wasn't minted for this verification id (`--verification "$VID"`; in production, the sign-in's `nonce`) |
