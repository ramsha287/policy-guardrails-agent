# Using the console

The console is where people run the platform: review held requests, change which guardrails run,
manage tenants and keys, act on the agent inventory, try requests, and read the decision log.
Agents never use it. It is served by the control plane at `/console/` (locally
http://localhost:8200/console/) and talks only to the control-plane API, with the same roles.

## Sign in and access

Paste your admin key (`cpk_…`). The key stays in that browser tab (`sessionStorage`), so closing
the tab — or **Sign out** — forgets it; a second tab signs in again. A revoked key is signed out on
its next request.

| Role | Can |
| --- | --- |
| `viewer` | Read everything in its scope |
| `reviewer` | Plus approve or reject held requests (sees the preview only) |
| `reviewer-raw` | `reviewer` plus opening the held payload (each view is logged) |
| `editor` | Read; change the catalog (tenants' agents, actions, keys) and assignments; request publishes; act on the inventory (run connectors, register/link/ignore, findings); use the Playground |
| `admin` | Everything except raw payloads: also the guardrail registry, publish approval, admin keys and (platform keys) discovery connectors |

A key is **platform-wide** or **limited to one tenant**. A tenant key sees only its tenant's
reviews, catalog, assignments, inventory, analytics and decisions, and never the platform-only
screens (Publish approvals, Activity log) or other tenants' assignments in published snapshots.
The menu only shows what your key can do; the API enforces the same rules. How people get keys:
[operations.md](operations.md#access-and-admin-keys).

## Screens

| Group | Screen | Use it to |
| --- | --- | --- |
| **Operate** | Overview | See today's traffic, blocks, held requests, publishes to approve and gateway health |
| | Review queue | Approve or reject requests held for a person, before they expire |
| | Publish approvals | Approve or reject a production publish or rollback another admin requested (platform) |
| | Agent inventory | Coverage, agents by state (managed, registered-unmanaged, shadow, stale), every discovered entity, open findings; register, link, ignore, accept or resolve |
| **Configure** | Pipeline | Choose which guardrails run per environment and stage, in shadow or enforce mode; diff, publish, roll back |
| | Simulate | Dry-run a request through the draft or the live pipeline on a real gateway. Nothing is enforced or audited |
| | Playground | Send a **real** agent request through the gateway with an agent's key (enforced and audited) |
| | Guardrails | Registered guardrail versions and which gateways have them; register a `guardrail.yaml`; deprecate |
| | Tenants & keys | Tenants, agents (trust, allowed tools), actions (risk), modifiers, gateway keys (create, bind to an agent, rate limit, revoke) |
| | Discovery connectors | The inventory's sources: add/edit (platform admins), Run now, run history |
| **Observe** | Gateways | Each gateway's heartbeat, snapshot and catalog versions, installed guardrails, last error |
| | Decision log | Every audited decision: outcome, reason codes, risk signals, guardrail results, advisor answers, hash-chain fields |
| | Analytics | Decisions over time, by stage and guardrail (enforce vs shadow), block rate, latency |
| | Advisors | The advisor pilot (answers, no-signal rate, agreement) and each tenant's hosted-advisor data policy |
| | Activity log | Who changed what, and when (platform keys) |
| | Admin keys | Give people access, and revoke it |

Decision log, Analytics and Advisors need `AUDIT_DSN` on the control plane. Simulate and
Playground need a gateway URL; the Playground also needs `PLAYGROUND_ENVIRONMENTS` (Compose: dev).

## Review a held request

When a guardrail escalates, or the decision table holds a risky request, the agent gets 202 and
waits; anything not decided within `REVIEW_TTL_MINUTES` (15) is blocked.

1. **Review queue** — pending items first, with a countdown. Filter by status and tenant.
2. Click a row. **Why it was held** shows the guardrail (or `gateway-risk` for a risk hold), its
   reason, the risk score and a preview: the first 500 characters of the held payload *after* any
   redaction an earlier guardrail applied.
3. Add a note and **Approve** (the agent's next poll returns `allow` and the held payload) or
   **Reject** (it returns `block`).

With `reviewer-raw`, **Show raw payload** decrypts the held payload after a confirmation; the view
is recorded on the review and in the change log.

## Change which guardrails run

1. **Pipeline** → pick the environment. Add, remove or reorder assignments; set each to `shadow`
   (runs, is logged, can't change the outcome) or `enforce`.
2. **Review & publish** shows the field-level diff. **dev/staging**: Publish goes live within
   seconds. **production**: Request publish → a *different* admin approves under Publish approvals.
3. Every published version can be rolled back from Pipeline.

A safe routine for a new guardrail: shadow → watch Analytics and the Decision log → try edge cases
in Simulate (draft) and the Playground (live) → enforce.

## Simulate vs Playground

| | Simulate | Playground |
| --- | --- | --- |
| Runs | the draft or the live snapshot, on a real gateway | the live pipeline, exactly like an agent call |
| Needs | an admin key with read on the tenant | an agent's gateway key (`gk_…`) and `catalog:write` on its tenant |
| Identity binding, session risk, advisors, decision table, verification | no | yes |
| Can hold a request in the Review queue | no | yes |
| Audited (Decision log, Analytics, discovery) | no | yes |
| Counts toward the agent's history (denials, trust, new resources) | no | yes |

### Playground

1. **Playground** (Configure). Paste an agent's gateway key — in Docker Compose,
   `DEMO_GATEWAY_API_KEY` from `/bootstrap/dev.env`. It stays in the page only.
2. Pick a **scenario** (normal request, PII, SSN, secret, prompt injection in a document or a tool
   result, a tool the agent may not use, PII to an external tool, a two-step exfiltration, a
   changed MCP tool, an agent with an open finding, an unregistered agent) or fill the form
   yourself. The expected result for the default dev setup is shown under the scenarios.
3. **Send as agent.** You see the HTTP status, decision and outcome, reason codes, the policy
   result, risk score/band/mode and each signal, every guardrail's mode and decision, and the
   payload the agent gets.
4. A held request shows **Check as the agent** (the agent's poll: `escalate` while pending,
   `allow` + payload after approval, `block` after rejection) and a link to the Review queue.
   Approve or reject in a second tab and check again.
5. **Open audit record** opens the request in the Decision log (it appears within a second or two).

Scenarios start a new session id; multi-step scenarios (exfiltration step 2) keep the session of
the previous step, because taint and labels are per session. Every request is real traffic: it is
in the audit log, and denials raise the agent's `REPEATED_DENIALS` signal for a while.

The control plane relays the request to the gateway's public API; the key is checked against the
catalog first (active, not expired, valid in that environment), never stored, and the change log
records who sent what (stage, agent, decision) — never the payload.

## Decision log

Filter by environment, tenant, decision, stage, agent and time window. Each row shows the agent and
action, the decision and the decision table's outcome, the risk score and a one-line *why* (the
telling reason codes, guardrails that didn't allow — marked *shadow* when they didn't count — and
policy denials). Click the time for the full record: request and session ids, reason, reason codes,
policy, identity assurance, snapshot, latency, the risk block with every signal, each guardrail's
result and finding *types*, the advisors' answers (never shown to the agent), the action descriptor,
and the payload SHA-256 with the record's hash-chain position.

## Agent inventory and findings

- **Agents** view: state, sources, owner guess. Click an entity for its reasons, sources and
  signals, relations and evidence. **Register agent** creates the registry entry and links it;
  **Link** says "this workload is registered agent X"; **Ignore** suppresses findings for N days.
- **Findings** view: open findings with severity. A changed MCP tool shows the approved and the new
  description. **Accept** = known and fine (for a tool change: pin the new definition); **Resolve** =
  fixed. Open findings on registered agents and changed tools raise those agents' and tools' risk
  at the gateway within seconds.
- **Discovery connectors**: add a source (platform admins), **Run now**, and look at **Runs**
  (counts, warnings, errors). Connector types and their config: [discovery.md](discovery.md#connectors).

## Connect an agent

1. **Tenants & keys** → tenant → register the agent (trust score, allowed tools).
2. **New API key** with that agent selected (a bound key can only act as that agent). The key is
   shown once.
3. Use it from the agent: [agent-integration.md](agent-integration.md).

## Common questions

**An agent gets 401.** The gateway key is wrong, revoked, expired or not valid in this environment.

**An agent gets 429.** It's over its rate limit (`Retry-After`). Raise the key's limit in Tenants
& keys if the traffic is legitimate.

**Everything is blocked in production for PII data.** The policy requires `ai-gateway-pii` to be
*enforced* for `PII` and `CONFIDENTIAL` data. Switch it from shadow to enforce.

**A risky request was allowed.** Check its Decision log entry: in `RISK_MODE=shadow` (the default)
the risk outcome is recorded as `would_outcome` but not enforced.

**My change isn't live.** Gateways shows each gateway's snapshot version. For production, check
that the publish was approved.

**The Decision log, Analytics or Advisors page is missing.** The control plane has no `AUDIT_DSN`.
