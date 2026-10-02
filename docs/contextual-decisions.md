# Contextual decisions (phase 6, sprint A)

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

## Settings

| Variable | Helm value | Default | Meaning |
| --- | --- | --- | --- |
| `RISK_MODE` | `gateway.contextual.riskMode` | `shadow` | `off`, `shadow` or `enforce` |
| `REQUIRE_BOUND_KEYS` | `gateway.contextual.requireBoundKeys` | `false` | Refuse keys not bound to an agent (403, `UNBOUND_KEY`) |
| `INTERNAL_DOMAINS` | `gateway.contextual.internalDomains` | empty | Comma-separated; destinations under these count as internal. Private IPs, `*.svc`, `*.cluster.local` and single-label hosts always do |
| `RISK_CONFIG_JSON` | `gateway.contextual.riskConfig` | `{}` | Overrides for the weights and limits in `RiskConfig` |
| `REDIS_URL` | (chart wires it) | — | Shared session state across replicas. Without it each replica keeps its own (bounded) memory |

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
| Band high | `verify`, which is `hold` until the verification engine ships (sprint B) |
| Band elevated, SQL read over 1,000 rows or unbounded | `allow_restricted` with `{"row_limit": 1000}` |
| Band elevated, write/send to an external destination | `verify` |
| Otherwise | the guardrails' own decision (never weakened) |

`allow_restricted` is only returned to callers that send `"accepts_obligations": true` (and so
promise to apply `obligations`). Everyone else gets `hold` (`OBLIGATIONS_UNSUPPORTED`), because a
caller that ignores a row limit is worse than one that waits for a reviewer.

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
database access could rebuild a consistent chain, so for strong guarantees, export each day's last
`record_hash` per chain to write-once storage (planned with the event outbox in sprint B).

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
- No verifiers yet: `verify` falls back to human review. Sprint B adds dry run, user
  confirmation and step-up.
