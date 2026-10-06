# Contextual decisions (phase 6, sprints A and B)

The gateway now decides with context, not just the single request: who the key really belongs
to, what the action actually does, what the session has done so far, and how unusual it is. It
is the first slice of the [agent security platform proposal](https://claude.ai/code/artifact/8ff001c0-15f0-4725-a362-10ec3d3bd45c).

What changed, in order of the request path:

| Step | What it does | Code |
| --- | --- | --- |
| Identity binding | A gateway key can be bound to one agent. A request whose `agent_id` differs is denied (403, `KEY_AGENT_MISMATCH`). Always enforced | `app/risk/contextual.py` |
| Action descriptor | Parses the tool call (SQL, HTTP, files, messages) into facts: verb, tables, columns, row count, destination | `app/context/descriptors.py` |
| Session state | Remembers per session: steps, denials, taint labels (`untrusted_input`, `holds:PII`), quarantine; per agent: targets seen in 90 days, volume baselines, trust penalties | `app/session/store.py` |
| Risk v2 | Inherent risk (phase 1) plus named, capped signals. Every point has a reason code | `app/risk/engine.py` |
| Decision table | Combines policy, guardrails and the risk band into one outcome | `app/risk/decision.py` |
| Decision records | Each audit row stores the outcome, reason codes, descriptor, risk and a hash-chain link | `app/audit/chain.py` |
| Verification (sprint B) | Turns `verify` into allow, a user confirmation or a human hold, with the cheapest evidence that closes the gap | `app/verify/` |
| AuthZEN API (sprint B) | The same decision for any AuthZEN policy enforcement point, no SDK needed | `app/gateway/authzen.py` |
| Decision events (sprint B) | A transactional outbox publishes every decision (and the audit chain heads) to Redis or a webhook | `app/events/` |

To check that all of this works on your install, follow [testing contextual decisions](testing-contextual-decisions.md).

Nothing here calls an LLM. Parsers and the decision table are deterministic and testable.

## Turning it on safely

`RISK_MODE` controls how much of this changes decisions:

| Mode | Effect |
| --- | --- |
| `off` | Descriptors only (still audited). No session state, no risk v2 |
| `shadow` (default) | Everything is computed, returned in `risk` and audited, but decisions are unchanged. `risk.would_outcome` shows what enforce mode would have done |
| `enforce` | The decision table's outcome is applied |

Recommended rollout:

1. **Bind keys.** In the console (Tenants & keys), bind every gateway key to its agent ("Bind").
   New keys are bound by default. Identity binding is enforced in every mode.
2. **Run shadow for 1–2 weeks.** Compare `outcome` with `risk->>'would_outcome'` in the audit log:

   ```sql
   SELECT risk->>'would_outcome' AS would, outcome, count(*)
   FROM audit.audit_events WHERE created_at > now() - interval '7 days' AND risk IS NOT NULL
   GROUP BY 1, 2 ORDER BY 3 DESC;
   ```

   Tune weights with `RISK_CONFIG_JSON` (Helm: `gateway.contextual.riskConfig`) until the holds
   are ones a reviewer agrees with.
3. **Enforce in dev and staging, then production.** Set `REQUIRE_BOUND_KEYS=true` in production
   once no A0 keys are left.

## Upgrading from 0.5

- **Upgrade gateways before binding keys.** A 0.5 gateway can't read a catalog that contains a bound
  key; it would keep serving its last good catalog and miss later revocations. The control plane
  therefore refuses to bind a key (422) while any gateway heard from in the last 15 minutes hasn't
  reported the `agent_bound_keys` capability in its heartbeat. Unbound keys keep working throughout.
- Migrations: gateway `0002` (nullable columns only, no table rewrite) and control plane `0003`.
- SDK 1.1 only sends `accepts_obligations` when you set it; a 0.5 gateway rejects that field (422),
  so set it only after the gateways are upgraded.

## Upgrading from sprint A

- Gateway migration `0003` adds `guardrail.outbox` (new table only). Nothing else changes in the
  database.
- `verify` no longer always becomes `hold` in enforce mode: SQL reads with a configured dry-run
  target can now be allowed after the dry run. With no verifiers configured the behaviour is the
  same as before (`VERIFY_NEEDS_HUMAN` instead of `VERIFY_AS_HOLD`). `VERIFICATION_ENABLED=false`
  restores sprint A exactly.
- SDK 1.2 adds `verification_channels`, `GuardResponse.verification`,
  `confirm_verification()`/`verification_status()` and `GuardrailVerificationRequired`. It is a
  subclass of `GuardrailBlocked` (not `GuardrailEscalated`: there is no escalation to wait for),
  so code that doesn't handle it treats the step as blocked. It is only raised for callers that
  send `verification_channels`.
  Like `accepts_obligations`, send `verification_channels` only to upgraded gateways.

## Settings

| Variable | Helm value | Default | Meaning |
| --- | --- | --- | --- |
| `RISK_MODE` | `gateway.contextual.riskMode` | `shadow` | `off`, `shadow` or `enforce` |
| `REQUIRE_BOUND_KEYS` | `gateway.contextual.requireBoundKeys` | `false` | Refuse keys not bound to an agent (403, `UNBOUND_KEY`) |
| `INTERNAL_DOMAINS` | `gateway.contextual.internalDomains` | empty | Comma-separated; destinations under these count as internal. Private IPs, `*.svc`, `*.cluster.local` and single-label hosts always do |
| `RISK_CONFIG_JSON` | `gateway.contextual.riskConfig` | `{}` | Overrides for the weights and limits in `RiskConfig` |
| `REDIS_URL` | (chart wires it) | — | Shared session state across replicas. Without it each replica keeps its own (bounded) memory |
| `VERIFICATION_ENABLED` | `gateway.verification.enabled` | `true` | `false` = every `verify` goes to human review (sprint A behaviour) |
| `VERIFY_OIDC_ISSUER`, `VERIFY_OIDC_AUDIENCE`, `VERIFY_OIDC_JWKS_URL` | `gateway.verification.oidc*` | empty | Your IdP, for user confirmation. All three needed. `VERIFY_OIDC_JWKS_JSON` takes a static JWKS instead of the URL |
| `VERIFY_USER_CLAIM` | `gateway.verification.userClaim` | `sub` | Token claim that must equal the request's `user_id` |
| `VERIFY_MAX_AUTH_AGE_SECONDS` | `gateway.verification.maxAuthAgeSeconds` | `600` | How recent the user's sign-in (`auth_time`, else `iat`) must be |
| `VERIFY_REQUIRED_ACR` | `gateway.verification.requiredAcr` | empty | Comma-separated `acr` values to require (MFA / step-up) |
| `VERIFY_REQUIRE_NONCE` | `gateway.verification.requireNonce` | `true` | The token's `nonce` must be the verification id |
| `VERIFY_DEV_SECRET` | — | empty | **Development only** (refused unless `GATEWAY_ENV=dev`, ≥ 32 chars): accept HS256 tokens from `python -m app.cli dev-user-token` |
| `VERIFY_SQL_DRY_RUN` | Secret key, `gateway.verification.sqlDryRun: true` | empty | JSON `{"tool name or resource": "read-replica DSN"}` |
| `VERIFY_DRY_RUN_MAX_ROWS` | `gateway.verification.dryRunMaxRows` | `10000` | Largest planner estimate a dry run accepts |
| `OUTBOX_SINKS` | `gateway.events.sinks` | empty | `redis`, `webhook` or both. Empty = no events written |
| `OUTBOX_WEBHOOK_URL`, `OUTBOX_WEBHOOK_SECRET` | `gateway.events.webhookUrl`, Secret key | empty | Webhook sink; the secret is required in production |
| `OUTBOX_RETENTION_DAYS` | `gateway.events.retentionDays` | `7` | Published events are deleted after this |

## Signals

Risk = min(100, inherent + signals). Inherent is the phase-1 score (action base risk plus
classification and environment modifiers).

| Code | Points (cap) | When |
| --- | --- | --- |
| `NEW_RESOURCE` | 15 | First time this agent touches this table/host/path in 90 days |
| `VOLUME_<n>X` | up to 25 | Rows requested vs this agent's p95 for the same target (needs 20 samples) |
| `VOLUME_NO_BASELINE` | 10 | ≥ 1,000 rows and no baseline yet |
| `UNBOUNDED_READ` | 15 | SQL read with no `LIMIT` and no `WHERE` |
| `SENSITIVE_THEN_EXTERNAL` | 30 | The session holds PII/confidential data and this action sends or writes to an external destination |
| `TAINTED_SESSION` | 15 | A tool call in a session that already read untrusted content (retrieval, external tool results) |
| `LOW_ASSURANCE` | 20 | Unbound key (A0) in production |
| `NEW_SESSION` / `NO_SESSION` | 5 | Session younger than 5 minutes, or no `session_id` |
| `REPEATED_DENIALS` | up to 20 | Earlier denials in this session, or by this agent in the last 15 minutes (10 each) |
| `DESTRUCTIVE_VERB` | 10 | Delete or admin operations |
| `UNKNOWN_TOOL` | 15 | The parser couldn't classify the tool call |
| `MULTIPLE_STATEMENTS` | 10 | More than one SQL statement |
| `LOW_CONFIDENCE` | up to 20 | Context was missing (store down, no session, unparsed action, no baseline) |
| `AGENT_FINDING` | 20 | The agent has an open inventory finding, e.g. `unmanaged_agent` (it also reaches models directly) ([discovery](discovery.md#findings-feed-the-gateways-risk)) |
| `TOOL_DEFINITION_CHANGED` | 25 | A tool call to an MCP tool whose definition changed after it was approved |
| `ADVISOR_RISK` | up to 20 | Enforcing [advisors](advisors.md) in the uncertain band (one aggregated code) |

**Bands** move with the agent's current trust T: low < 30 + 0.2·T, elevated < min(80, 55 + 0.2·T),
high < 80, critical ≥ 80.

**Trust** is the catalog base trust minus penalties that fade with a half-life. Three denials in a
session cost 10 points (7-day half-life). Good behaviour never raises trust above the base.

## Decision table

Strongest first: `deny` > `quarantine_session` > `hold` > `verify` > `throttle` > `modify` >
`allow_restricted` > `allow`.

| Situation | Outcome |
| --- | --- |
| Identity check fails | `deny` (403) |
| Policy denies | `deny` (403) |
| Session quarantined (5 denials in the session, or 10 across all of the agent's sessions within 15 minutes; enforce mode only) | `quarantine_session` (403) |
| Band critical | `hold` (human review, 202) |
| Band high | `verify` (see [verification](#verification)) |
| Band elevated, SQL read over 1,000 rows or unbounded | `allow_restricted` with `{"row_limit": 1000}` |
| Band elevated, write/send to an external destination | `verify` |
| Otherwise | the guardrails' own decision (never weakened) |

`allow_restricted` is only returned to callers that send `"accepts_obligations": true` (and so
promise to apply `obligations`). Everyone else gets `hold` (`OBLIGATIONS_UNSUPPORTED`), because a
caller that ignores a row limit is worse than one that waits for a reviewer.

## Verification

`verify` means "not confident enough yet". The verification engine says exactly which of five
dimensions is short and picks the cheapest evidence that closes it:

| Dimension | Question | Closed by |
| --- | --- | --- |
| identity | Is this really that agent? | agent-bound key (A1); a human reviewer |
| authorization | Did the person the agent acts for want this? | user confirmation; a human reviewer |
| resource | Do we know what this touches? | SQL dry run (EXPLAIN on a read replica) |
| behaviour | Is this consistent with the session? | user confirmation; a human reviewer |
| effect | Do we know what happens if we allow it? | SQL dry run |

What an action needs: a SQL read needs resource and effect; a write or send to an external
destination needs authorization; delete, admin and execute need authorization and effect; an
unparsed tool needs authorization; a tainted session adds behaviour; production adds identity.

| Verifier | Runs | Result |
| --- | --- | --- |
| SQL dry run | inline, ~ms | `EXPLAIN (FORMAT JSON)` (never executed) on a read replica in a read-only transaction. Passes when the planner estimates ≤ `VERIFY_DRY_RUN_MAX_ROWS` rows → `allow` (`VERIFIED`, `EVIDENCE_DRY_RUN`). Too many rows or an error → `hold` |
| User confirmation | asynchronous | Only when the request says it can (`verification_channels: ["user_confirmation"]`), has a `user_id`, and the gateway has an identity provider configured. The response is `verify` (HTTP 202) with a `verification` object; your app shows `verification.summary` to the user and sends their sign-in token to `POST /v1/verifications/{id}/confirm`; the agent then retries the identical request → `allow`. A "no" → `deny` (`USER_REJECTED`) |
| Human review | asynchronous | Everything else: the existing review queue (`hold`, `VERIFY_NEEDS_HUMAN`) |

Evidence is bound to one request: a hash of tenant, agent, stage, action and every request field
(payload, `arguments`, `tool_metadata`, user, session, classification, delegation chain). It
expires after 10 minutes and is used once, atomically: of two identical retries racing on one
confirmation, only one is allowed. A confirmation for "send report.pdf to ann@acme.com" can't be
replayed for a different body, recipient or user.

The user's token must be signed by your IdP (JWKS), be meant for `VERIFY_OIDC_AUDIENCE`, belong to
the request's `user_id`, come from a sign-in within `VERIFY_MAX_AUTH_AGE_SECONDS`, and carry
`nonce` = the verification id. The nonce means your app signs the user in again for this
confirmation (an OIDC authorization request with `nonce=<verification id>`, typically
`prompt=login` or `max_age=0`), so a token the agent might have seen, such as the user's everyday
access token, can't confirm anything. If your IdP flow can't set a nonce, set
`VERIFY_REQUIRE_NONCE=false`: any recent token of the user is then accepted, and a confirmation
sent with the requesting agent's own (bound) key is refused, so give the host app its own key.
An unbound (A0) key can't be told apart from the agent, so don't let agents hold unbound keys
when the nonce check is off. Shadow mode only reports what would
happen (`risk.would_outcome`: `verify` when a dry run or user confirmation would be tried, `hold`
when only a human can close the gap); nothing runs or is stored.

```text
agent  --POST /v1/guard/tool {..., "user_id": "u1", "verification_channels": ["user_confirmation"]}-->  gateway
       <--202 {"outcome": "verify", "verification": {"id": "9f…", "summary": "research-agent wants to send data to evil.example.org (external destination)"}}
app    shows the summary to u1 and signs u1 in again with nonce=9f…; u1 approves
app    --POST /v1/verifications/9f…/confirm  Authorization: Bearer <that token>  {"approve": true}-->  gateway
agent  --the identical POST /v1/guard/tool-->  gateway  <--200 {"outcome": "allow", "reason_codes": [..., "VERIFIED", "EVIDENCE_USER_CONFIRMATION"]}
```

## AuthZEN API

Any policy enforcement point that speaks the OpenID AuthZEN Authorization API 1.0 (API gateways,
MCP servers, mesh filters) can ask the gateway directly. It runs the same pipeline as
`POST /v1/guard/tool`, including identity binding, verification and audit.

```bash
curl -s localhost:8100/access/v1/evaluation -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{
  "subject":  {"type": "agent", "id": "research-agent", "properties": {"user_id": "u1", "session_id": "s1"}},
  "action":   {"name": "db.query"},
  "resource": {"type": "database", "id": "analytics", "properties": {"arguments": {"sql": "SELECT name FROM products LIMIT 5"}}},
  "context":  {"data_classification": "INTERNAL"}}'
# {"decision": true, "context": {"outcome": "allow", "reason_codes": [...], "decision_id": "...", "risk": {...}}}
```

`decision` is true only when the PEP may go ahead exactly as asked: `allow`, or `allow_restricted`
when `context.accepts_obligations` is true (apply `context.obligations`). A guardrail that changes
the arguments (redaction) is true only with `context.accepts_modifications: true`, and the PEP must
use `context.modified_arguments`; otherwise false with `MODIFY_UNSUPPORTED_BY_PEP`. `verify` and
`hold` are false with `context.verification` or `context.escalation_id`.

Batch: `POST /access/v1/evaluations` with up to 50 `evaluations` (each overrides the top-level
subject/action/resource/context) and `options.evaluations_semantic` = `execute_all` (default),
`deny_on_first_deny` or `permit_on_first_permit`. Without an `evaluations` array it answers like a
single evaluation. Each evaluation counts against the key's rate limit like one guard call. Metadata: `GET /.well-known/authzen-configuration`.

## Decision events

With `OUTBOX_SINKS` set, every audit batch also writes one `decision.made.v1` event per decision
into `guardrail.outbox`, **in the same transaction**: an event exists if and only if the decision
was recorded. A relay in each gateway publishes them (oldest first, `FOR UPDATE SKIP LOCKED`, so
replicas share the work) and marks them published; published rows are pruned after 7 days.

| Sink | Delivery |
| --- | --- |
| `redis` | `PUBLISH events.decision.made.v1 <CloudEvent JSON>` (and `events.audit.chain_heads.v1`). Fan-out only: subscribers that are offline miss events |
| `webhook` | `POST OUTBOX_WEBHOOK_URL` with a JSON array of CloudEvents (`application/cloudevents-batch+json`), headers `X-Guardrail-Timestamp` and `X-Guardrail-Signature: sha256=HMAC(OUTBOX_WEBHOOK_SECRET, "<timestamp>.<body>")`. Non-2xx is retried with backoff; nothing is lost while the receiver is down |

Delivery is at least once (dedupe on the event `id`, which is the audit record id). Events carry
names, codes, scores and hashes, never payload text, like the audit log. Every hour (and at
shutdown) the relay also publishes `audit.chain_heads.v1`: the last committed `chain_seq` and
`record_hash` of each audit chain. Keep those somewhere the database admins can't write (a SIEM, object storage
with a retention lock): `verify-audit-chain` must reach the same hashes, which closes the "someone
with full database access rebuilt the chain" gap.

Verifying the webhook signature (Python):

```python
mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(f"sha256={mac}", request.headers["X-Guardrail-Signature"]) and abs(time.time() - int(ts)) < 300
```

## Response fields (all optional, older clients ignore them)

```json
{
  "decision": "escalate",
  "outcome": "hold",
  "reason_codes": ["RISK_CRITICAL", "NEW_RESOURCE", "VOLUME_40X", "TAINTED_SESSION"],
  "obligations": {},
  "assurance": "A1",
  "risk": {"score": 100, "band": "critical", "trust": 80, "confidence": 1.0, "mode": "enforce",
           "would_outcome": "hold", "signals": [{"code": "NEW_RESOURCE", "points": 15, "detail": "..."}]}
}
```

OPA also receives `identity`, `descriptor`, `session` and `risk_v2` in its input (never payload
text), so policies can use them; see the header of `policies/guardrails/authz.rego`.

## Decision records and the hash chain

Each audit row now has `outcome`, `reason_codes`, `descriptor` (names and counts, never values),
`risk` and `assurance`, plus `chain_id`, `chain_seq`, `prev_hash` and `record_hash`. Each gateway
process keeps one chain per tenant. Check them with:

```bash
python -m app.cli verify-audit-chain --days 30 [--tenant acme]   # exit 1 if a record was changed or removed
```

The chain shows tampering by anyone who bypasses the append-only trigger. Someone with full
database access could rebuild a consistent chain, so for strong guarantees turn on the event
outbox and keep the hourly `audit.chain_heads.v1` events outside the database (see
[decision events](#decision-events)).

## Known limits (honest list)

- The SQL parser is a conservative tokenizer, not a grammar. It recognises statement types,
  tables, selected columns, `LIMIT`/`FETCH FIRST`/`TOP` and `WHERE`. Anything unclear becomes
  `unknown`, which costs risk.
- Opaque tools (no SQL, URL, path or recipients) start as `UNKNOWN_TOOL`. Expect friction until
  tools send `tool_metadata.kind` (`sql`, `http`, `file`) or structured arguments.
- Volume baselines need 20 allowed requests per agent and target before they count, so new agents
  run on cold-start defaults for a while.
- Sessions are keyed by tenant, agent and `session_id`, so one agent can't taint or quarantine
  another's session. Redis calls time out after 150 ms; a slow Redis lowers confidence (stricter
  decisions) instead of adding latency.
- Without Redis, session state is per replica: a session spread over replicas looks newer and
  cleaner on each one than it is. Run Redis in production.
- Verifiers so far: SQL dry run and user confirmation. HTTP/file dry runs, step-up
  authentication and workload attestation (identity above A1) come later; until then those gaps go
  to human review.
- Once a send to a new external host is allowed (for example after a user confirmation), that
  host is no longer "new" for the agent, so the next send to it in the same session may be low
  risk and need no confirmation. Policies that must confirm every external send should say so in
  OPA (`input.descriptor.destination == "external"`).
- The dry-run estimate is the planner's guess. Keep table statistics fresh (`ANALYZE`) on the
  replica, and treat the row limit as a "roughly how big" check, not a count.
- Decision events from different gateway replicas are not globally ordered; within one chain,
  `chain_seq` gives the order.
