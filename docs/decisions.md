# How decisions are made: risk, policy, advisors, verification

The gateway decides with context, not just the single request: who the key really belongs to,
what the action actually does, what the session has done so far, and how unusual it is. Nothing
on this path calls an LLM except optional hosted advisors; parsers, signals and the decision table
are deterministic and unit-tested. The order of the steps is in
[architecture.md](architecture.md#one-request-step-by-step).

| Step | What it does | Code (`services/guardrail-gateway/`) |
| --- | --- | --- |
| Identity binding | A key bound to one agent can't act as another (403 `KEY_AGENT_MISMATCH`). Always enforced | `app/risk/contextual.py` |
| Action descriptor | Parses the tool call (SQL, HTTP, files, messages) into facts: verb, tables, columns, row count, destination | `app/context/descriptors.py` |
| Session state | Per session: steps, denials, taint labels (`untrusted_input`, `holds:PII`), quarantine. Per agent: targets seen in 90 days, volume baselines, trust penalties | `app/session/store.py` |
| Risk v2 | Inherent risk plus named, capped signals; every point has a reason code | `app/risk/engine.py` |
| Policy | OPA: trust, risk, allowed tools, delegation depth, required guardrails | `policies/guardrails/authz.rego` |
| Advisors | Optional classifiers in the uncertain band; capped points or "ask a person", never permit | `app/advise/` |
| Decision table | Combines policy, guardrails, advisors and the risk band into one outcome | `app/risk/decision.py` |
| Verification | Turns `verify` into allow (with evidence), a user confirmation or a human hold | `app/verify/` |
| Decision records | Each audit row stores the outcome, reason codes, descriptor, risk and a hash-chain link | `app/audit/chain.py` |

## `RISK_MODE`

| Mode | Effect |
| --- | --- |
| `off` | Descriptors only (still audited). No session state, no risk v2, no advisors, no decision table |
| `shadow` (default) | Everything is computed, returned in `risk` and audited, but decisions are unchanged. `risk.would_outcome` shows what enforce would have done. Sessions are recorded; nothing is quarantined |
| `enforce` | The decision table's outcome is applied, verification runs, quarantines apply |

Identity binding, OPA and the guardrails apply in every mode. Rollout:

1. **Bind keys.** Bind every gateway key to its agent (console: Tenants & keys → Bind). New keys
   created with an agent are bound.
2. **Run shadow for 1–2 weeks.** Compare `outcome` with `risk.would_outcome` — in the console's
   **Decision log**, or in SQL:

   ```sql
   SELECT risk->>'would_outcome' AS would, outcome, count(*)
   FROM audit.audit_events WHERE created_at > now() - interval '7 days' AND risk IS NOT NULL
   GROUP BY 1, 2 ORDER BY 3 DESC;
   ```

   Tune weights with `RISK_CONFIG_JSON` (Helm `gateway.contextual.riskConfig`) until the holds are
   ones a reviewer agrees with.
3. **Enforce in dev and staging, then production.** Set `REQUIRE_BOUND_KEYS=true` in production
   once no unbound (A0) keys are left.

## Inherent risk and trust

- **Trust** is the agent's base trust from the catalog (unknown agent: 0) minus penalties that
  fade with a 7-day half-life: three denials in a session cost 10 points. Good behaviour never
  raises trust above the base.
- **Inherent risk** = `min(100, action base risk + classification modifier + environment
  modifier)`. The most specific action rule wins (exact resource beats a glob, then the longer
  prefix). An unknown action scores 100.

The dev seed: agents `research-agent` (trust 80, any tool), `support-bot` (70, `crm.lookup`,
`database.read`), `untrusted-agent` (20, no tools); actions `llm.chat` 10, `retrieval.search` 20,
`database.read` 30 (40 on `customer_db`), `database.write` 60, `crm.lookup` 30, `http.post` 30,
`ticket.create` 20; modifiers PII +20, CONFIDENTIAL +10, production +10.

## Risk signals

Risk = min(100, inherent + signals).

| Code | Points (cap) | When |
| --- | --- | --- |
| `NEW_RESOURCE` | 15 | First time this agent touches this table/host/path in 90 days |
| `VOLUME_<n>X` | up to 25 | Rows requested vs this agent's p95 for the same target (needs 20 samples) |
| `VOLUME_NO_BASELINE` | 10 | ≥ 1,000 rows and no baseline yet |
| `UNBOUNDED_READ` | 15 | SQL read with no `LIMIT` and no `WHERE` |
| `SENSITIVE_THEN_EXTERNAL` | 30 | The session holds PII/confidential data (or the request is classified so) and this action sends or writes to an external destination |
| `TAINTED_SESSION` | 15 | A tool call in a session that already read untrusted content (retrieval, external tool results) |
| `LOW_ASSURANCE` | 20 | Unbound key (A0) in production |
| `NEW_SESSION` / `NO_SESSION` | 5 | Session younger than 5 minutes, or no `session_id` |
| `REPEATED_DENIALS` | up to 20 | Earlier denials in this session, or by this agent in the last 15 minutes (10 each) |
| `DESTRUCTIVE_VERB` | 10 | Delete or admin operations |
| `UNKNOWN_TOOL` | 15 | The parser couldn't classify the tool call |
| `MULTIPLE_STATEMENTS` | 10 | More than one SQL statement |
| `LOW_CONFIDENCE` | up to 20 | Context was missing (store down, no session, unparsed action, no baseline) |
| `AGENT_FINDING` | 20 | The agent has an open `unmanaged_agent` inventory finding ([discovery](discovery.md#findings-feed-the-gateways-risk)) |
| `TOOL_DEFINITION_CHANGED` | 25 | A call to an MCP tool whose definition changed after it was approved |
| `ADVISOR_RISK` | up to 20 | Enforcing [advisors](#advisors) in the uncertain band (one aggregated code) |

**Bands** move with the agent's current trust T: low < 30 + 0.2·T, elevated < min(80, 55 + 0.2·T),
high < 80, critical ≥ 80. For a trust-80 agent: low < 46, elevated < 71, high < 80.

## Policy (OPA)

The starter policy (`policies/guardrails/authz.rego`, tested with `opa test policies`):

| Rule | Where |
| --- | --- |
| Agent trust at least 50 | production |
| Action risk at most 70 | production |
| Delegation chains at most 3 deep | everywhere |
| Tool on the agent's allowed list (`*` allows all) | tool stage |
| `ai-gateway-pii` must run, **enforced**, for `PII` or `CONFIDENTIAL` data (an obligation the engine checks) | input, retrieval, tool, output |

OPA also receives `identity`, `descriptor`, `session` and `risk_v2` (never payload text). The
starter policy doesn't use them yet — the decision table does — but your own rules can, for
example "confirm every external send": `input.descriptor.destination == "external"`.

## Decision table

Strongest first: `deny` > `quarantine_session` > `hold` > `verify` > `modify` >
`allow_restricted` > `allow`. (`throttle` is reserved in the type but never produced.)

| Situation | Outcome |
| --- | --- |
| Identity check fails | `deny` (403) |
| Policy denies | `deny` (403) |
| Session quarantined (5 denials in the session, or 10 across the agent's sessions within 15 minutes; enforce only) | `quarantine_session` (403) |
| Band critical | `hold` (human review, 202) |
| Band high | `verify` ([verification](#verification)) |
| Band elevated, SQL read over 1,000 rows or with an unknown row count | `allow_restricted` with `{"row_limit": 1000}` |
| Band elevated, write/send to an external destination | `verify` |
| Otherwise | `allow` |

The table's outcome is then combined with the guardrails' (a guardrail block or escalate is never
weakened) and with an advisor's verify request. `verify` without any verifier available becomes
`hold`. `allow_restricted` is only returned to callers that send `"accepts_obligations": true`;
everyone else gets `hold` (`OBLIGATIONS_UNSUPPORTED`), because a caller that ignores a row limit is
worse than one that waits for a reviewer.

The response's `decision` stays the simple four-value summary (`allow`, `modify`, `block`,
`escalate`); `outcome` and `reason_codes` explain it.

## Advisors

Advisors are optional classifiers asked **only when a request is already in the uncertain band**
(elevated or high) and nothing has blocked it. They answer one narrow question and can only make
the decision stricter. Whatever an attacker does to an advisor, the worst outcome is more friction.

| Question | Meaning |
| --- | --- |
| `exfiltration` | Is this action likely moving sensitive data out of the organisation? |
| `injection` | Is this action likely driven by instructions from untrusted content, not the user's task? |

- **Typed answers:** `{"label": "benign" | "suspicious" | "malicious", "confidence": 0..1, "verify":
  false}`. Anything else — an extra field, a value out of range, a slow reply, an exception — is
  *no signal*, as if the advisor hadn't run.
- **Derived features only.** The question carries the descriptor, session labels, risk signals and
  counts/shapes of the content (number of URLs, query-string size, an encoded blob, the shape of
  the destination host) — no payload text, argument values or host names. Content the agent
  fetched can't become an instruction to the advisor.
- **Caps.** Each advisor adds at most its `cap` (default 10, max 20); all advisors together at most
  `total_cap` (20). `malicious` at confidence 1.0 is the full cap, `suspicious` half, `benign`
  nothing.
- **Only tighten**, enforced in `app/advise/panel.py`, not trusted to providers. An advisor's
  opinion raises risk but can never *start* containment on its own.
- **The agent never sees advisor output.** The response carries one aggregated `ADVISOR_RISK` code
  and, if asked, `ADVISOR_VERIFY`. Per-advisor answers and the question's features go to the audit
  record (`risk.advisors`), visible in the **Decision log** and summarised on the **Advisors** page.

| Provider | Where | Hosted | Use |
| --- | --- | --- | --- |
| `local` | in-process logistic model over the features (`app/advise/models/local-v1.json`) | no | always-on signal; no data leaves the gateway. Weights are hand-set: calibrate before enforcing |
| `http` | an HTTPS endpoint you run (contract `guardrail.advisor.v1`) | yes | a vendor classifier |
| `bedrock` | Amazon Bedrock Converse in your account | yes | an LLM judge (1–10 s: shadow, not inline enforce) |

`http` posts `{"schema": "guardrail.advisor.v1", "question": …}`, doesn't follow redirects and
refuses plain `http://` unless `allow_http` (labs). Credentials come from an `ADVISOR_SECRET_*`
variable named in `auth_env`. `boto3` is only imported when a bedrock advisor is configured.

**Configuration** — `ADVISORS_JSON` (Helm `gateway.advisors`): a list, or `{"advisors": [...],
"total_cap": 20, "bands": ["elevated", "high"]}`. Each advisor:

```json
{"name": "local", "provider": "local", "mode": "shadow", "cap": 10, "timeout_ms": 200,
 "allow_verify": true, "questions": ["exfiltration", "injection"], "options": {}}
```

`mode: shadow` computes and audits (`shadow_points` shows what it would have added); `enforce`
counts. A malformed `ADVISORS_JSON`, unknown provider, duplicate name or bad cap stops the gateway
at start-up. Docker Compose runs the local advisor in shadow by default.

**Tenant data policy for hosted advisors.** A hosted advisor sees a tenant's request only when the
tenant allows the request's data class *and* every sensitive class the session already holds. Off
by default. Set it on the console's **Advisors** page or with
`PUT /cp/v1/tenants/{t}/advisor-policy {"data_classes": ["INTERNAL", "PUBLIC"]}`. Turning it on
needs every live gateway to report the `advisors_v1` capability (422 otherwise). Local advisors
ignore it.

**Measuring the pilot.** The **Advisors** page (`GET /cp/v1/analytics/advisors`) shows per advisor
the answers vs no-signal rate, label mix, latency and *agreement*: of the requests it flagged, how
many the deterministic path stopped anyway. Look at `flagged_released` before enforcing: an
advisor is worth enforcing when it beats the deterministic baseline there without raising the hold
rate beyond what reviewers can handle.

### Calibrating the local advisor

People's decisions on requests the advisors saw become labels:

| Label | When |
| --- | --- |
| 1 | a reviewer rejected the held request, or the user rejected the confirmation (`USER_REJECTED`) |
| 0 | a reviewer approved it, or the user confirmed it (`EVIDENCE_USER_CONFIRMATION`) |
| weak 0 | released without a person deciding (including a bare `VERIFIED`, which can be machine evidence); only with `--include-released`, and the calibrator leaves these out unless `--include-weak` |

```bash
# control plane (needs AUDIT_DSN)
python -m app.cli advisor-training-set --out advisor-set.jsonl --days 30 [--tenant acme]
# gateway: L2 logistic fit (Newton), 20% deterministic holdout, AUC, precision/recall, calibration
python -m app.advise.calibrate --data advisor-set.jsonl --out local-v2.json --report calibration.json --min-auc 0.75
```

It refuses to train on fewer than 50 rows or 10 of each label. Run the new weights in shadow
(`options.weights_path`), compare on the Advisors page, then enforce.

## Verification

`verify` means "not confident enough yet". The engine says which of five dimensions is short and
picks the cheapest evidence that closes it (dry run 5, user confirmation 500, human 10000):

| Dimension | Question | Closed by |
| --- | --- | --- |
| identity | Is this really that agent? | agent-bound key (A1); a human reviewer |
| authorization | Did the person the agent acts for want this? | user confirmation; a human reviewer |
| resource | Do we know what this touches? | SQL dry run |
| behaviour | Is this consistent with the session? | user confirmation; a human reviewer |
| effect | Do we know what happens if we allow it? | SQL dry run |

A SQL read needs resource and effect; a write or send to an external destination needs
authorization; delete, admin and execute need authorization and effect; an unparsed tool needs
authorization; a tainted session adds behaviour; production adds identity.

| Verifier | Runs | Result |
| --- | --- | --- |
| SQL dry run (`VERIFY_SQL_DRY_RUN`) | inline | `EXPLAIN (FORMAT JSON)` (never executed) on a read replica, read-only transaction, 2 s timeout. ≤ `VERIFY_DRY_RUN_MAX_ROWS` estimated rows → `allow` (`VERIFIED`, `EVIDENCE_DRY_RUN`); more, or an error → `hold` |
| User confirmation | asynchronous | Only when the request sends `verification_channels: ["user_confirmation"]` and a `user_id`, and the gateway has an IdP (`VERIFY_OIDC_*`). 202 with `outcome: "verify"` and a `verification` object; your app shows `verification.summary` and posts the user's fresh sign-in token to `POST /v1/verifications/{id}/confirm`; the agent retries the identical request → `allow`. A "no" → `deny` (`USER_REJECTED`) |
| Human review | asynchronous | Everything else: the review queue (`hold`, `VERIFY_NEEDS_HUMAN`) |

Evidence is bound to one request (a hash of tenant, agent, stage, action and every request
field), expires after 10 minutes and is used once, atomically. The user's token must be signed by
your IdP, be meant for `VERIFY_OIDC_AUDIENCE`, belong to the request's `user_id`, come from a sign-in
within `VERIFY_MAX_AUTH_AGE_SECONDS`, and carry `nonce` = the verification id — so a token the agent
might have seen can't confirm anything. If your IdP can't set a nonce, `VERIFY_REQUIRE_NONCE=false`
accepts any recent token of the user and refuses a confirmation sent with the requesting agent's
own bound key. In shadow mode nothing runs or is stored; `risk.would_outcome` says `verify` or
`hold`.

```text
agent  --POST /v1/guard/tool {..., "user_id": "u1", "verification_channels": ["user_confirmation"]}-->  gateway
       <--202 {"outcome": "verify", "verification": {"id": "9f…", "summary": "research-agent wants to send data to evil.example.org (external destination)"}}
app    shows the summary to u1 and signs u1 in again with nonce=9f…; u1 approves
app    --POST /v1/verifications/9f…/confirm  Authorization: Bearer <that token>  {"approve": true}-->  gateway
agent  --the identical POST /v1/guard/tool-->  gateway  <--200 {"outcome": "allow", "reason_codes": [..., "VERIFIED", "EVIDENCE_USER_CONFIRMATION"]}
```

For local testing, `VERIFY_DEV_SECRET` (refused unless `GATEWAY_ENV=dev`) lets
`python -m app.cli dev-user-token --user u1 --verification <id>` mint tokens.

## AuthZEN API

Any policy enforcement point that speaks OpenID AuthZEN 1.0 (API gateways, MCP servers, mesh
filters) can ask the gateway directly. It runs the same pipeline as `POST /v1/guard/tool`.

```bash
curl -s localhost:8100/access/v1/evaluation -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{
  "subject":  {"type": "agent", "id": "research-agent", "properties": {"user_id": "u1", "session_id": "s1"}},
  "action":   {"name": "db.query"},
  "resource": {"type": "database", "id": "analytics", "properties": {"arguments": {"sql": "SELECT name FROM products LIMIT 5"}}},
  "context":  {"data_classification": "INTERNAL"}}'
# {"decision": true, "context": {"outcome": "allow", "reason_codes": [...], "decision_id": "...", "risk": {...}}}
```

`decision` is true only when the PEP may go ahead exactly as asked: `allow`, or `allow_restricted`
with `context.accepts_obligations: true` (apply `context.obligations`). A guardrail that changes the
arguments is true only with `context.accepts_modifications: true` (use
`context.modified_arguments`); otherwise false with `MODIFY_UNSUPPORTED_BY_PEP`. `verify` and `hold`
are false with `context.verification` or `context.escalation_id`. Batch: `POST
/access/v1/evaluations` (up to 50; `execute_all`, `deny_on_first_deny`, `permit_on_first_permit`),
each counted against the key's rate limit. Metadata: `GET /.well-known/authzen-configuration`.

## Decision events

With `OUTBOX_SINKS` set, every audit batch also writes one `decision.made.v1` CloudEvent per
decision into `guardrail.outbox`, in the same transaction: an event exists if and only if the
decision was recorded. A relay in each gateway publishes them (oldest first, `FOR UPDATE SKIP
LOCKED`) and prunes them after `OUTBOX_RETENTION_DAYS`.

| Sink | Delivery |
| --- | --- |
| `redis` | `PUBLISH events.decision.made.v1 <CloudEvent>` (and `events.audit.chain_heads.v1`). Fan-out only: offline subscribers miss events |
| `webhook` | `POST OUTBOX_WEBHOOK_URL`, a JSON array of CloudEvents, headers `X-Guardrail-Timestamp` and `X-Guardrail-Signature: sha256=HMAC(secret, "<timestamp>.<body>")`. Retried with backoff; nothing is lost while the receiver is down |

Delivery is at least once (dedupe on the event `id`). Events carry names, codes, scores and
hashes, never payload text. Every hour (and at shutdown) the relay publishes `audit.chain_heads.v1`,
the last `chain_seq` and `record_hash` of each chain. Keep those outside the database (a SIEM,
object storage with a retention lock): `verify-audit-chain` must reach the same hashes.

```python
mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(f"sha256={mac}", request.headers["X-Guardrail-Signature"]) and abs(time.time() - int(ts)) < 300
```

## Decision records and the hash chain

Each audit row has `outcome`, `reason_codes`, `descriptor` (names and counts, never values),
`risk` (with advisor answers), `assurance`, and `chain_id`, `chain_seq`, `prev_hash`,
`record_hash`. Each gateway process keeps one chain per tenant.

```bash
python -m app.cli verify-audit-chain --days 30 [--tenant acme]   # exit 1 if a record was changed or removed
```

The chain shows tampering by anyone who bypasses the append-only trigger. Someone with full
database access could rebuild a consistent chain, so for strong guarantees export the chain heads
(above).

## Response fields

```json
{
  "decision": "escalate",
  "outcome": "hold",
  "reason_codes": ["RISK_CRITICAL", "NEW_RESOURCE", "VOLUME_40X", "TAINTED_SESSION"],
  "obligations": {},
  "assurance": "A1",
  "escalation_id": "…",
  "risk": {"score": 100, "band": "critical", "trust": 80, "confidence": 1.0, "mode": "enforce",
           "would_outcome": "hold", "signals": [{"code": "NEW_RESOURCE", "points": 15, "detail": "..."}]}
}
```

## Known limits

- The SQL parser is a conservative tokenizer: statement types, tables, selected columns,
  `LIMIT`/`FETCH FIRST`/`TOP`, `WHERE`. Anything unclear becomes `unknown`, which costs risk.
- Opaque tools (no SQL, URL, path or recipients) start as `UNKNOWN_TOOL` until they send
  `tool_metadata.kind` (`sql`, `http`, `file`) or structured arguments.
- Volume baselines need 20 allowed requests per agent and target; new agents run on cold-start
  defaults for a while.
- Scores depend on history: `REPEATED_DENIALS` and trust penalties last for days, so the same
  request can land in a different band for an agent that was recently denied.
- Without Redis, session state is per replica. Run Redis in production. Redis calls time out after
  150 ms; a slow Redis lowers confidence (stricter) instead of adding latency.
- Verifiers: SQL dry run and user confirmation. HTTP/file dry runs, step-up authentication and
  workload attestation come later; those gaps go to human review.
- Once a send to a new external host is allowed, the host is no longer "new" for that agent. If
  every external send must be confirmed, say so in OPA.
- The dry-run estimate is the planner's guess; keep statistics fresh (`ANALYZE`) on the replica.
- Decision events from different replicas are not globally ordered; `chain_seq` orders one chain.
