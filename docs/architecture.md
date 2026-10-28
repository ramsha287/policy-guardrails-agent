# Architecture

How the service is put together, how a request moves through it, and what is built, tested,
partly built or still planned. Every claim here was checked against the code and tests on `main`;
the [status table](#what-is-built-and-how-well-it-is-tested) says how.

## Components

```mermaid
%%{init: {"theme": "base", "darkMode": false, "fontFamily": "Helvetica, Arial, sans-serif", "fontSize": "16px", "themeVariables": {"background": "#ffffff", "primaryColor": "#eef6ff", "primaryBorderColor": "#93c5fd", "primaryTextColor": "#1f2937", "secondaryColor": "#f3f0ff", "tertiaryColor": "#f8fafc", "lineColor": "#64748b", "textColor": "#1f2937", "clusterBkg": "#f8fafc", "clusterBorder": "#cbd5e1", "edgeLabelBackground": "#ffffff", "titleColor": "#1f2937"}, "flowchart": {"curve": "basis", "nodeSpacing": 40, "rankSpacing": 64, "padding": 16, "htmlLabels": true}}}%%
flowchart TB
  subgraph ENV["Enterprise environments"]
    direction LR
    AG["`**AI agents**<br/>SDK · LangGraph · CrewAI<br/>OpenAI proxy · AuthZEN`"]
    PE["`**People**<br/>console in a browser`"]
    SRC["`**Infrastructure sources**<br/>audit logs · Kubernetes<br/>DNS · OpenAI · Bedrock · MCP`"]
  end

  subgraph DISC["Discovery plane"]
    direction TB
    CON["`**Connectors**<br/>read-only · scheduled`"]
    NORM["`**Normalize**<br/>resolve · classify · reconcile`"]
  end

  subgraph ENF["Enforcement points"]
    GW["`**Guardrail gateway** · :8100<br/>/v1/guard · proxy · AuthZEN`"]
  end

  subgraph IDC["Identity and configuration"]
    direction LR
    CP["`**Control plane** · :8200<br/>snapshots · catalog<br/>publish approvals`"]
    ID["`**Keys and agent binding**<br/>gk_ agent keys<br/>cpk_ admin roles`"]
  end

  subgraph INV["Agent inventory"]
    IV["`**Agents, entities, findings**<br/>shadow · unmanaged<br/>stale`"]
  end

  subgraph PDP["Decision plane"]
    direction LR
    C["`**Context**<br/>identity · trust`"]
    R["`**Risk**<br/>signals · bands`"]
    P["`**Policy**<br/>OPA · deny is final`"]
    G["`**Guardrails**<br/>PII · secrets<br/>injection · memory`"]
    A["`**Advisors**<br/>tighten only`"]
    D["`**Decide**<br/>decision table · verify`"]
    C --> R --> P --> G --> A --> D
  end

  subgraph OUT["Outcomes"]
    direction LR
    HUM["`**Human in the loop**<br/>review queue · approvals`"]
    EVD["`**Evidence and audit**<br/>decision log · hash chain`"]
    RSP["`**Response and containment**<br/>planned`"]
  end

  EBUS["`**Event bus**<br/>decision events · Redis · webhook`"]

  AG -- "gk_ key" --> GW
  PE -- "cpk_ key" --> CP
  SRC -.-> CON
  CON --> NORM --> IV
  IV -. "findings raise risk" .-> PDP
  GW --> PDP
  ID -- "agent binding" --> PDP
  CP -- "snapshots · catalog" --> GW
  PDP --> HUM
  PDP --> EVD
  PDP -.-> RSP
  EVD --> EBUS

  classDef actor fill:#f5f3ff,stroke:#a78bfa,stroke-width:1.25px,color:#1f2937
  classDef external fill:#ffffff,stroke:#94a3b8,stroke-width:1.5px,stroke-dasharray:5 4,color:#1f2937
  classDef discovery fill:#f0fdfa,stroke:#5eead4,stroke-width:1.25px,color:#1f2937
  classDef inventory fill:#f1f5f9,stroke:#94a3b8,stroke-width:1.25px,color:#1f2937
  classDef control fill:#ccfbf1,stroke:#2dd4bf,stroke-width:1.5px,color:#1f2937
  classDef enforce fill:#eff6ff,stroke:#60a5fa,stroke-width:1.25px,color:#1f2937
  classDef step fill:#ffffff,stroke:#0d9488,stroke-width:1.25px,color:#1f2937
  classDef guard fill:#dcfce7,stroke:#4ade80,stroke-width:1.5px,color:#1f2937
  classDef audit fill:#fefce8,stroke:#eab308,stroke-width:1.25px,color:#1f2937
  classDef planned fill:#ffffff,stroke:#94a3b8,stroke-width:1.25px,stroke-dasharray:5 4,color:#475569
  class AG,PE actor
  class SRC external
  class CON,NORM discovery
  class IV inventory
  class CP,ID control
  class GW enforce
  class C,R,P,A,D step
  class G guard
  class HUM,EVD audit
  class EBUS inventory
  class RSP planned
  style ENV fill:#fafafa,stroke:#e5e7eb
  style PDP fill:#f0fdfa,stroke:#5eead4,stroke-width:2px
  style OUT fill:#fafafa,stroke:#e5e7eb
```

| Component | Code | What it owns |
| --- | --- | --- |
| **Guardrail gateway** | `services/guardrail-gateway` | The agent-facing API. Every decision is made here, in one function (`app/gateway/flow.py: run_stage`) shared by `/v1/guard/{stage}`, proxy mode and AuthZEN |
| **OPA** | `policies/guardrails/authz.rego` | Whether the action is allowed at all (trust, risk, tools, delegation depth, required guardrails) |
| **Guardrail plugins** | `app/plugins/` | Content checks: `ai-gateway-pii`, `secrets`, `prompt-injection`, `topic-limits`, `content-moderation`, `memory-firewall`, `noop` |
| **Advisors** | `app/advise/` | Optional classifiers for the uncertain risk band; can only tighten |
| **Control plane** | `services/guardrail-control-plane` | Source of truth for configuration and people's decisions: tenants, keys, agents, actions, guardrail registry, snapshots, publish approvals, review queue, discovery and inventory, admin keys, change log |
| **Console** | `apps/console` | React app served by the control plane at `/console`. Talks only to `/cp/v1` and `/inv/v1` |
| **AI Gateway** | `services/ai-gateway` | The existing PII redaction service (Presidio) behind `ai-gateway-pii` |
| **Memory Firewall** | `services/memory-firewall` | HTTP adapter around the unmodified Memory Firewall library: per-memory writer gate and source trust (`VectorGuard`), injection-text scan, signed provenance, event log, checkpoint self-test. Behind the `memory-firewall` guardrail and the console's Memory Firewall page |
| **SDK** | `packages/guardrail-sdk` | Agent client and hooks, framework integrations, the plugin contract, conformance and evaluation tools, shared documents |
| **Helm chart** | `deploy/helm/guardrail-platform` | Kubernetes/k3s install with NetworkPolicies, alerts and a dashboard |

## One request, step by step

An agent calls `POST /v1/guard/{input|retrieval|tool|output}` with its gateway key, before it
sends a prompt, uses retrieved text, runs (or reads the result of) a tool, or returns an answer.

```mermaid
%%{init: {"theme": "base", "darkMode": false, "fontFamily": "Helvetica, Arial, sans-serif", "fontSize": "16px", "themeVariables": {"background": "#ffffff", "primaryColor": "#eef6ff", "primaryBorderColor": "#93c5fd", "primaryTextColor": "#1f2937", "textColor": "#1f2937", "actorBkg": "#eef6ff", "actorBorder": "#93c5fd", "actorTextColor": "#1f2937", "actorLineColor": "#94a3b8", "signalColor": "#475569", "signalTextColor": "#1f2937", "labelBoxBkgColor": "#f3f0ff", "labelBoxBorderColor": "#c4b5fd", "labelTextColor": "#1f2937", "loopTextColor": "#1f2937", "noteBkgColor": "#ecfdf5", "noteBorderColor": "#6ee7b7", "noteTextColor": "#1f2937", "activationBkgColor": "#ccfbf1", "activationBorderColor": "#5eead4", "sequenceNumberColor": "#1f2937", "altSectionBkgColor": "#f8fafc"}, "sequence": {"actorMargin": 60, "messageMargin": 44}}}%%
sequenceDiagram
  autonumber
  participant Ag as Agent
  participant GW as Gateway
  participant S as Session store (Redis)
  participant O as OPA
  participant G as Guardrails
  participant Adv as Advisors
  participant CP as Control plane
  participant DB as Audit log
  Ag->>GW: POST /v1/guard/{stage} (gk_ key, agent, action, session, payload)
  GW->>GW: auth + rate limit, normalise text, build context (trust, inherent risk)
  GW->>GW: identity binding (bound key must match agent_id)
  GW->>S: session view (taint, labels, denials, targets, baselines)
  GW->>GW: action descriptor + risk v2 signals → score, band
  GW->>O: policy input (scores, tool, classification, identity, descriptor, session, risk)
  O-->>GW: allow / deny + obligations
  GW->>G: run assigned guardrails in order (shadow ones only recorded)
  Note over G: local plugins in-process, remote ones call<br/>AI Gateway (PII) and Memory Firewall (retrieved memory)
  G-->>GW: allow / modify / block / escalate
  GW->>Adv: only if band is elevated or high and nothing blocked
  Adv-->>GW: capped points / verify request (enforce mode) or shadow record
  GW->>GW: decision table (+ verification: SQL dry run, user confirmation)
  alt held for a person
    GW->>CP: file review (encrypted payload)
    GW-->>Ag: 202 escalate + escalation_id (agent polls /v1/escalations/{id})
  else
    GW-->>Ag: 200 allow / modify (payload) / block, or 403 deny
  end
  GW->>S: record step (taint, labels, denials, volumes)
  GW->>DB: audit row (hash-chained) + outbox event, written asynchronously
```

1. **Authenticate.** The `X-API-Key` hash is looked up in the catalog; per-key rate limit (429).
   No snapshot loaded → 503 (fail-closed).
2. **Context.** Trust is the agent's base trust (unknown agent: 0). Inherent risk is the action's
   base risk plus classification and environment modifiers (unknown action: 100).
3. **Identity binding.** A key bound to one agent can't act as another (`KEY_AGENT_MISMATCH`,
   403). Enforced in every `RISK_MODE`.
4. **Risk v2.** A deterministic descriptor of the action (SQL, HTTP, file, message) plus session
   state give named, capped signals (`NEW_RESOURCE`, `TAINTED_SESSION`,
   `SENSITIVE_THEN_EXTERNAL`, `AGENT_FINDING`, `TOOL_DEFINITION_CHANGED`, …) → score and band.
   See [decisions.md](decisions.md#risk-signals).
5. **Policy.** OPA decides whether the action is allowed; a denial is final (403) and no
   guardrail runs.
6. **Guardrails.** The snapshot's assignments for this environment, stage, tenant and agent run in
   order; strictest wins (block > escalate > modify > allow); errors follow `failure_mode`
   (`fail_closed` blocks). Shadow assignments run and are audited but change nothing.
7. **Advisors** (optional). Asked only in the elevated and high bands, from derived features,
   never text. Enforcing advisors add at most 20 points or ask for verification; they can't
   permit anything.
8. **Decision table** (`RISK_MODE=enforce`): critical → hold; high → verify; elevated external
   write → verify; elevated unbounded SQL read → allow with a row limit; combined with the
   guardrails' result, strongest wins. In `shadow` (the default) the table's outcome is only
   recorded as `risk.would_outcome`.
9. **Verification** turns `verify` into `allow` with evidence (SQL dry run on a read replica, the
   user's confirmation through your IdP) or into `hold` for a person.
10. **Hold.** The payload is filed in the control plane's review queue (Fernet-encrypted) and the
    agent gets 202 with an `escalation_id`. A reviewer approves (the agent's poll returns `allow`
    and the payload) or rejects; undecided after 15 minutes = blocked. Control plane unreachable
    = blocked.
11. **Record and audit.** The session is updated (taint after untrusted content, `holds:PII`
    after sensitive data, denials, quarantine in enforce mode). The audit row (decision, outcome,
    reason codes, risk and signals, guardrail results with finding *types and offsets*, the
    descriptor, advisor answers, payload SHA-256, hash-chain link) is queued and batch-written;
    raw payload text is never stored. With `OUTBOX_SINKS`, a `decision.made.v1` event is written in
    the same transaction.

## The Memory Firewall path

The Memory Firewall library is vendored, byte for byte, in `services/memory-firewall/vendor`
(checked against `SHA256SUMS` by a test), and `services/memory-firewall/app/firewall.py` is the only
code that imports it. Agents' retrieved memory reaches it through the gateway; people reach it
through the control plane.

```mermaid
%%{init: {"theme": "base", "darkMode": false, "fontFamily": "Helvetica, Arial, sans-serif", "fontSize": "16px", "themeVariables": {"background": "#ffffff", "primaryColor": "#eef6ff", "primaryBorderColor": "#93c5fd", "primaryTextColor": "#1f2937", "secondaryColor": "#f3f0ff", "tertiaryColor": "#f8fafc", "lineColor": "#64748b", "textColor": "#1f2937", "clusterBkg": "#f8fafc", "clusterBorder": "#cbd5e1", "edgeLabelBackground": "#ffffff", "titleColor": "#1f2937"}, "flowchart": {"curve": "basis", "nodeSpacing": 40, "rankSpacing": 64, "padding": 16, "htmlLabels": true}}}%%
flowchart LR
  AG["Agent<br/>retrieval hook"] -- "POST /v1/guard/retrieval<br/>chunks + metadata.source_type, writer" --> GW

  subgraph Gateway["Guardrail gateway"]
    GW["Guardrail engine"] --> PL["memory-firewall plugin<br/>labels · ids · writer gate patterns"]
  end

  subgraph MF["services/memory-firewall · :8300"]
    direction TB
    API["FastAPI adapter<br/>X-API-Key · limits · errors"] --> FW["firewall.py<br/>integration boundary"]
    FW --> LIB["Memory Firewall library<br/>vendor/ · verbatim @ 807b972<br/>guard.vector_guard · guard.keys · guard.events<br/>scan.scanner · lab.tamper (self-test)"]
  end

  PL -- "POST /v1/memory/inspect" --> API
  CP["Control plane<br/>/cp/v1/memory-firewall/*"] -- "status · events · inspect · scan · self-test" --> API
  UI["Console<br/>Memory Firewall page"] -- "cpk_ key" --> CP
  LIB --> KEYS[("Data volume<br/>Ed25519 keys · events.jsonl<br/>selftest scratch DBs")]
  PL -. "drop · hold · block<br/>findings: MEMORY_QUARANTINED<br/>MEMORY_INJECTION_TEXT" .-> GW

  classDef client fill:#f3f0ff,stroke:#a78bfa,stroke-width:1.5px,color:#1f2937
  classDef edge fill:#e0f2fe,stroke:#38bdf8,stroke-width:1.5px,color:#1f2937
  classDef control fill:#ccfbf1,stroke:#2dd4bf,stroke-width:1.5px,color:#1f2937
  classDef guard fill:#dcfce7,stroke:#4ade80,stroke-width:1.5px,color:#1f2937
  classDef mfw fill:#d1fae5,stroke:#10b981,stroke-width:2.5px,color:#1f2937
  classDef store fill:#f1f5f9,stroke:#94a3b8,stroke-width:1.5px,color:#1f2937
  classDef external fill:#ffffff,stroke:#94a3b8,stroke-width:1.5px,stroke-dasharray:5 4,color:#1f2937
  classDef finding fill:#fef9c3,stroke:#facc15,stroke-width:1.5px,color:#1f2937
  class AG,UI client
  class GW,PL edge
  class CP control
  class API,FW guard
  class LIB mfw
  class KEYS store
```

1. The agent sends retrieved memory to `POST /v1/guard/retrieval` like any other chunks.
2. If an assignment includes `memory-firewall`, the plugin labels each chunk (source, writer,
   authorized) and calls `POST /v1/memory/inspect` once per request.
3. The adapter calls `VectorGuard.admit` per chunk (writer gate, then source trust; admitted
   memory is signed into a provenance record) and `scan_text` when the scan is on. Every write,
   rejection and quarantine is appended to `events.jsonl` with MITRE ATLAS `AML.T0080`, with ids
   and reasons only.
4. The plugin drops, holds or blocks per its config; the engine combines it with the other
   guardrails (strongest wins) and the audit row records the findings' types and locations.
5. The service being down is a guardrail error: with `fail_closed` (the default) the request is
   blocked.

The console's page reads `/cp/v1/memory-firewall/status` (never fails: an unreachable service is
a state), the event log, and can run checks and the checkpoint self-test, which executes the
library's `lab.tamper.ATTACKS` in a subprocess against scratch databases. Details:
[memory-firewall.md](memory-firewall.md).

## Configuration flow

```mermaid
%%{init: {"theme": "base", "darkMode": false, "fontFamily": "Helvetica, Arial, sans-serif", "fontSize": "16px", "themeVariables": {"background": "#ffffff", "primaryColor": "#eef6ff", "primaryBorderColor": "#93c5fd", "primaryTextColor": "#1f2937", "secondaryColor": "#f3f0ff", "tertiaryColor": "#f8fafc", "lineColor": "#64748b", "textColor": "#1f2937", "clusterBkg": "#f8fafc", "clusterBorder": "#cbd5e1", "edgeLabelBackground": "#ffffff", "titleColor": "#1f2937"}, "flowchart": {"curve": "basis", "nodeSpacing": 40, "rankSpacing": 64, "padding": 16, "htmlLabels": true}}}%%
flowchart LR
  E["Editor<br/>Pipeline · Tenants & keys"] -- "working set" --> CP["Control plane"]
  CP -- "publish: compile + validate<br/>production: second admin approves" --> S[("Snapshot vN<br/>immutable")]
  CP -- "catalog change: automatic" --> C[("Catalog vN<br/>tenants · key hashes · agents<br/>actions · inventory flags")]
  S & C -- "Redis push + ETag poll 30 s" --> GW["Gateways"]
  GW -- "disk cache" --> GW
  GW -- "heartbeat: installed guardrails<br/>versions · capabilities" --> CP

  classDef client fill:#f3f0ff,stroke:#a78bfa,stroke-width:1.5px,color:#1f2937
  classDef edge fill:#e0f2fe,stroke:#38bdf8,stroke-width:1.5px,color:#1f2937
  classDef control fill:#ccfbf1,stroke:#2dd4bf,stroke-width:1.5px,color:#1f2937
  classDef guard fill:#dcfce7,stroke:#4ade80,stroke-width:1.5px,color:#1f2937
  classDef mfw fill:#d1fae5,stroke:#10b981,stroke-width:2.5px,color:#1f2937
  classDef store fill:#f1f5f9,stroke:#94a3b8,stroke-width:1.5px,color:#1f2937
  classDef external fill:#ffffff,stroke:#94a3b8,stroke-width:1.5px,stroke-dasharray:5 4,color:#1f2937
  classDef finding fill:#fef9c3,stroke:#facc15,stroke-width:1.5px,color:#1f2937
  class E client
  class CP control
  class GW edge
  class S,C store
```

- **Snapshots** (one per environment): which guardrail versions run where, in which mode, with
  which config. Published from the working set; production needs a second admin; every version
  can be rolled back. Publishing refuses a snapshot that wouldn't compile (unknown version,
  unsupported stage, config not matching the manifest schema, version not installed on the live
  gateways).
- **Catalog** (one, all tenants): tenants, gateway key hashes, agents and their allowed tools,
  action base risk, score modifiers, hosted-advisor data policy, and the inventory flags (open
  `unmanaged_agent` findings per agent, changed MCP tools). Republished on every change.
- Gateways keep the last good copies on disk. Control plane down → they keep serving; nothing
  cached at start-up → not ready (503). A snapshot that doesn't compile on a gateway (a guardrail
  version it lacks, a `${VAR}` it doesn't have) is rejected there and the previous one keeps
  serving; the error shows on `/ready`, in the heartbeat and on the console's Gateways page.
- Snapshots, catalog versions and the change log are append-only (a database trigger rejects
  UPDATE and DELETE). Snapshot versions look like `production-00012-3fa9c2d1` (environment,
  sequence, content hash).
- `CONFIG_SOURCE=file` (no control plane) reads `config/snapshots/<env>.json` and the gateway's own
  tables instead. It has no review queue (escalate becomes block) and no inventory flags.

## Discovery feeds risk

```mermaid
%%{init: {"theme": "base", "darkMode": false, "fontFamily": "Helvetica, Arial, sans-serif", "fontSize": "16px", "themeVariables": {"background": "#ffffff", "primaryColor": "#eef6ff", "primaryBorderColor": "#93c5fd", "primaryTextColor": "#1f2937", "secondaryColor": "#f3f0ff", "tertiaryColor": "#f8fafc", "lineColor": "#64748b", "textColor": "#1f2937", "clusterBkg": "#f8fafc", "clusterBorder": "#cbd5e1", "edgeLabelBackground": "#ffffff", "titleColor": "#1f2937"}, "flowchart": {"curve": "basis", "nodeSpacing": 40, "rankSpacing": 64, "padding": 16, "htmlLabels": true}}}%%
flowchart LR
  K["Connectors<br/>gateway · kubernetes · dns_log<br/>openai_admin · aws_bedrock · mcp"] --> O["Observations"]
  O --> E["Entities<br/>merged by strong keys"] --> CL["Classification<br/>confirmed · probable · not agent"]
  CL --> RC["Reconcile with the registry<br/>managed · registered_unmanaged · shadow · stale"]
  RC --> F["Findings<br/>shadow_agent · unmanaged_agent · stale_agent<br/>tool_definition_changed"]
  F -- "catalog: open_findings, flagged_tools" --> GW["Gateway risk<br/>AGENT_FINDING +20<br/>TOOL_DEFINITION_CHANGED +25"]

  classDef client fill:#f3f0ff,stroke:#a78bfa,stroke-width:1.5px,color:#1f2937
  classDef edge fill:#e0f2fe,stroke:#38bdf8,stroke-width:1.5px,color:#1f2937
  classDef control fill:#ccfbf1,stroke:#2dd4bf,stroke-width:1.5px,color:#1f2937
  classDef guard fill:#dcfce7,stroke:#4ade80,stroke-width:1.5px,color:#1f2937
  classDef mfw fill:#d1fae5,stroke:#10b981,stroke-width:2.5px,color:#1f2937
  classDef store fill:#f1f5f9,stroke:#94a3b8,stroke-width:1.5px,color:#1f2937
  classDef external fill:#ffffff,stroke:#94a3b8,stroke-width:1.5px,stroke-dasharray:5 4,color:#1f2937
  classDef finding fill:#fef9c3,stroke:#facc15,stroke-width:1.5px,color:#1f2937
  class K external
  class O,E,CL,RC control
  class F finding
  class GW edge
```

Connectors are read-only (list APIs, one audit query, MCP `tools/list` only). An MCP tool's
definition is hashed and pinned the first time it is seen; a later change opens a
`tool_definition_changed` finding until someone accepts it (which pins the new definition) or the
server reverts. Details: [discovery.md](discovery.md).

## Audit, analytics and events

| Store | Written by | Read by |
| --- | --- | --- |
| `audit.audit_events` (monthly partitions, append-only trigger, 12-month retention, per-process hash chain) | gateway, asynchronously, with a disk spool when Postgres is down | control plane through `AUDIT_DSN`: **Analytics**, **Advisors**, **Decision log**, the `gateway` discovery connector, the advisor training set; `python -m app.cli verify-audit-chain` |
| `guardrail.outbox` (same transaction as the audit rows) | gateway | the gateway's relay → Redis `events.decision.made.v1` and/or a signed webhook; hourly `audit.chain_heads.v1` |
| `control.change_log` (append-only) | control plane: every configuration change, review view and decision, publish, playground request | **Activity log** (platform keys) |
| `control.reviews` | control plane (payload encrypted, preview in clear) | **Review queue**, the gateway's escalation poll |

The audit record never contains payload text: guardrail findings carry types, offsets and scores,
the descriptor carries table/host names and counts, and the payload is kept as a SHA-256.

## Trust boundaries

- **Agents** hold gateway keys (`gk_`). A key can be bound to one agent (identity assurance A1);
  unbound keys are A0 and can be refused with `REQUIRE_BOUND_KEYS=true`.
- **People** hold admin keys (`cpk_`) with roles (`viewer`, `reviewer`, `reviewer-raw`, `editor`,
  `admin`), platform-wide or limited to one tenant. Tenant keys only see their tenant.
- **Gateway ↔ control plane** use a shared `INTERNAL_TOKEN`, optionally mTLS on separate internal
  ports (`mtls.mode=app`) or a mesh (`linkerd`).
- **Untrusted content** (retrieved documents, tool results) never becomes an instruction to the
  platform: guardrails read it as data, advisors only see derived counts, and the session is
  tainted so later external actions score higher.
- **Fail-closed** everywhere: no snapshot, OPA down, a `fail_closed` guardrail erroring, the review
  queue unreachable, an expired review — all block.

## What is built and how well it is tested

*Tested* means automated tests in this repository exercise it (unit tests with fakes, the
Postgres suites, the console's browser smoke test, or the live end-to-end suites that CI runs on
the Docker Compose stack). *Partial* means it works but has a gap listed next to it.

| Area | Status | Evidence |
| --- | --- | --- |
| Guard API (4 stages), OPA, guardrail engine, shadow/enforce, fail-closed | Implemented, tested | `test_api.py`, `test_pipeline.py`, `opa test policies`, `tests/e2e/*` (live) |
| `ai-gateway-pii` (Presidio) | Implemented, tested | `test_ai_gateway_pii*.py` (fake), the live e2e suites against real Presidio in CI, and an 880-case precision/recall report (report-only until a baseline is agreed) |
| `secrets`, `prompt-injection`, `topic-limits` | Implemented, tested | `test_content_guardrails.py`, `test_security_flows.py` (live). `prompt-injection` is a heuristic: no labelled set ships; measure in shadow first |
| `content-moderation` | Implemented, unit-tested | Tested against a mocked endpoint only; needs `MODERATION_API_KEY` to try for real |
| Identity binding, descriptors, sessions, risk v2, decision table, `RISK_MODE` | Implemented, tested | `test_contextual_flow.py`, `test_risk.py`, `test_descriptors.py`, live `test_security_flows.py` in shadow and enforce |
| Verification: SQL dry run, user confirmation (OIDC) | Implemented, tested | `test_verify.py`, `test_verification_flow.py` (dev-secret tokens). Not tested against a real IdP |
| Review queue loop (hold → decide → agent poll) | Implemented, tested | `test_services.py`, `test_api.py`, live `test_security_flows.py`, console smoke |
| Advisors: local model, panel rules, calibration | Implemented, tested | `test_advisors.py`, `test_calibrate.py`, live exfiltration flow. Local weights are hand-set until calibrated |
| Advisors: `http` and `bedrock` providers | Partial | Contract tests with stubs; not run against a real endpoint or Bedrock |
| Memory Firewall service, `memory-firewall` guardrail, console page | Implemented, tested | `services/memory-firewall/tests` (real library, incl. the five checkpoint attacks), gateway and control-plane `test_memory_firewall.py`, console vitest + smoke on the mock. Not in the Helm chart; not in the live e2e suites |
| AuthZEN API | Implemented, tested | `test_authzen.py`, `test_api.py` |
| Decision events (outbox → Redis/webhook), audit hash chain | Implemented, tested | `test_outbox.py`, `integration/test_postgres.py` |
| Control plane: catalog, registry, publish, two-person approval, rollback, RBAC | Implemented, tested | `test_services.py` (memory + Postgres), `test_api.py`, `tests/e2e/test_control_plane.py` (live) |
| Discovery: `gateway`, `dns_log`, `mcp` connectors, inventory, findings → risk | Implemented, tested | `test_discovery.py`, live `test_security_flows.py` (shadow agent, `AGENT_FINDING`, `TOOL_DEFINITION_CHANGED`) |
| Discovery: `kubernetes`, `openai_admin`, `aws_bedrock` connectors | Partial | Unit-tested against recorded/fake API responses; not run against real accounts in CI |
| Console (all screens, incl. Playground and Decision log) | Implemented, tested | vitest, Playwright smoke on a mock and on the live stack |
| Proxy mode (`/v1/chat/completions`) | Partial | `test_proxy.py`. A `verify` or `hold` comes back as 403 `guardrail_escalated`; there is no way to resume a held request through the proxy |
| Helm chart, mTLS, SOPS secrets | Implemented, partly tested | Rendered and schema-validated in CI (`kubeconform`), TLS handshake tests; no cluster install in CI |
| Fast-path latency (Gate 1: p99 < 15 ms) | Measured locally | `python -m app.bench`: p99 4.4 ms with OPA on a dev container; CI job is report-only |
| Exfiltration attack success (Gate 1: < 5%) | Not measured here | Measured by your security team against staging with an established framework ([testing.md](testing.md#gate-1)) |
| NATS JetStream event bus, Envoy `ext_authz` enforcement point, MCP elicitation for user confirmation, an MCP proxy | Planned | Redis/webhook outbox, the guard API/AuthZEN and the verification API stand in for them today |
| Response engine (cut a shadow agent's egress), model-based injection detection, grounding, tool-argument rules, step/cost limits, more discovery sources (CloudTrail, Azure, GCP) | Planned | — |
