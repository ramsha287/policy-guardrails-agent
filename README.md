# Custom Guardrail Platform for AI Agents

Plug-in guardrails for AI agents with no NeMo dependency. Every request goes through
**Security Gateway → Context Builder → Policy Engine (OPA) → Guardrail Engine → Agent**.
Every decision is written to an append-only audit log.

The first guardrail is the existing **AI Security Gateway** (Presidio PII redaction). It is
plugged in over HTTP as `ai-gateway-pii` and covers prompts, retrieved chunks, tool arguments
and results, and responses.

- Connect an agent: [docs/agent-integration.md](docs/agent-integration.md)
- Add a guardrail: [docs/adding-a-guardrail.md](docs/adding-a-guardrail.md)
- Manage guardrails, tenants and reviews: the console at `/console` ([apps/console](apps/console/README.md)) or the API ([docs/control-plane.md](docs/control-plane.md))
- Deploy on k3s: [docs/deployment.md](docs/deployment.md) · on call: [docs/runbooks](docs/runbooks/README.md) · security: [docs/security/pentest-plan.md](docs/security/pentest-plan.md)
- Measure one: [eval/README.md](eval/README.md)

All five phases of the build plan are done:

| Phase | Status | What's in it |
| --- | --- | --- |
| 0. Foundations | Done | Monorepo, `guardrail-sdk`, CI, Docker Compose with Postgres, Redis and OPA |
| 1. Gateway + engine core | Done | `/v1/guard/{stage}`, auth, normalization, context and scoring, OPA with Rego, pipeline, audit |
| 2. ai-gateway adapter | Done | `ai-gateway-pii@1.0.0` for input and output; ai-gateway changes 1, 4, 6, 7, 10 |
| 3. Retrieval + tool stages | Done | `ai-gateway-pii@1.1.0` on all four stages, ai-gateway changes 2, 3, 5 plus the Presidio thread pool, agent hooks (plain Python, LangGraph, CrewAI), sample agent, 880-case evaluation set |
| 4. Control plane | Done | `guardrail-control-plane` (:8200): guardrail registry, versioned snapshots with two-person approval and rollback, tenant catalog, human review queue for ESCALATE, RBAC with tenant-scoped keys, simulate; gateways sync without redeploy; ai-gateway changes 8, 9 |
| 5. Hardening + production | Done | Operator console with the human review UI (React), k3s Helm chart (NetworkPolicies, HPA, PDB, retention CronJob, optional in-chart Postgres/Redis), mTLS (Linkerd, or app-level on internal ports with cert-manager), SOPS secrets, per-key rate limits, durable audit spool, Prometheus alerts + runbooks + Grafana dashboard, OpenAI-compatible proxy mode, multi-arch images, pen-test plan |

## Repository layout

```text
packages/guardrail-sdk/           contracts, Guardrail base class, manifest, conformance + evaluation, agent client and hooks
  guardrail_sdk/integrations/     guard_tool, LangGraph nodes/retriever, CrewAI tool/inputs/output
services/guardrail-gateway/       :8100  gateway + context builder + OPA client + engine + audit
  app/plugins/ai_gateway_pii/     first guardrail: 1.0.0 (input/output), 1.1.0 (all four stages)
  app/plugins/noop/               reference local guardrail / template
  config/snapshots/<env>.json     which guardrails run where with CONFIG_SOURCE=file (seed for the control plane)
  alembic/                        guardrail + audit schemas (own version table in `guardrail`)
services/guardrail-control-plane/ :8200  registry, snapshots, catalog, review queue, RBAC (schema `control`), serves /console
apps/console/                     operator console + human review UI (React, TypeScript, Vite); mock control plane + Playwright smoke test
deploy/helm/guardrail-platform/   k3s/Kubernetes chart (values-k3s.yaml, values-cloud.yaml), alerts, Grafana dashboard
deploy/secrets/                   SOPS + age setup and the Secret template
services/ai-gateway/              existing PII redaction platform (project-service :8000, instant-redaction :8001)
policies/guardrails/              Rego authorization policy + tests
examples/sample_agent/            framework-free agent using all four stages
eval/                             labelled PII dataset (880 cases) + generator + eval config
tests/e2e/                        sample agent against a fake gateway and the live stack
docs/                             agent integration, adding guardrails, control plane, deployment, runbooks, security
```

## Run it

```bash
docker compose up --build
docker compose exec guardrail-gateway cat /bootstrap/dev.env   # DEMO_GATEWAY_API_KEY=gk_...
docker compose exec guardrail-control-plane cat /bootstrap/cp.env   # CP_ADMIN_KEY, CP_APPROVER_KEY
```

Open **http://localhost:8200/console/** and sign in with `CP_ADMIN_KEY`. The console covers the
review queue, the pipeline (shadow/enforce, publish, rollback), approvals with the second key,
simulate, tenants and keys, gateways, analytics and the activity log. With mTLS between the
gateway and the control plane: `docker compose -f docker-compose.yml -f docker-compose.mtls.yml up --build`.

The one-shot `guardrail-bootstrap` container does three things. It runs the migrations, and
it seeds a `demo` tenant with agents, an action catalog and score modifiers. It also creates
a redaction project and a service API key in ai-gateway's project-service. It writes the
generated keys to the `bootstrap` volume, and the gateway reads them from there at start-up.

In Compose the gateway runs with `CONFIG_SOURCE=control_plane`. On the first run the control plane
imports the seeded tenant and `config/snapshots/*.json`, and from then on it is the source of truth.
Change guardrails, keys and scores through its API ([docs/control-plane.md](docs/control-plane.md)),
not the snapshot files. Production publishes need a second admin key to approve.

```bash
KEY=gk_...   # from dev.env
curl -s localhost:8100/v1/guard/input -H "X-API-Key: $KEY" -H 'content-type: application/json' -d '{
  "agent_id": "research-agent", "action": "llm.chat", "user_id": "u1",
  "data_classification": "PII",
  "payload": {"text": "Email jane.doe@example.com about invoice EMP-123456"}
}' | jq '{decision, reason, text: .payload.text, trust_score, risk_score}'
```

With the dev snapshot you get `decision: "modify"`, and the email and employee ID come back
redacted. A US SSN on input returns `block`. On the retrieval stage, chunks with an SSN or card
number are dropped. On the tool stage, PII sent to `http.*`, `email.*`, `slack.*` or `webhook.*`
tools is blocked, and PII in tool results is redacted.

## From an agent

```python
from guardrail_sdk import GuardClient, GuardHooks, GuardrailBlocked

async with GuardClient("http://guardrail-gateway:8100", api_key, agent_id="research-agent") as client:
    hooks = GuardHooks(client, user_id=user_id, data_classification="PII")
    try:
        prompt = await hooks.before_llm(user_text)            # input
        chunks = await hooks.on_retrieval(search(prompt))     # retrieval
        answer = await hooks.after_llm(await llm(prompt, chunks))   # output
    except GuardrailBlocked as exc:
        answer = f"Request blocked: {exc.reason}"
```

Tools are wrapped with `guard_tool` (tool stage, before and after the call). LangGraph and CrewAI
adapters are described in [docs/agent-integration.md](docs/agent-integration.md).

## API

`POST /v1/guard/{stage}` where `stage` is `input`, `retrieval`, `tool`, `output` or `agent`.
Authenticate with the `X-API-Key` header. The tenant comes from the key, and the environment
comes from the gateway's configuration.

| Status | Meaning |
| --- | --- |
| 200 | `decision` is `allow`, `modify` (use the returned `payload`) or `block` (a guardrail blocked) |
| 202 | `decision` is `escalate`: the payload is held for human review. Poll `GET /v1/escalations/{escalation_id}` |
| 403 | `decision` is `block` because OPA denied the request (`policy.reason`) |
| 401 / 422 / 413 | Bad key / invalid body / body over 1 MB |
| 429 | Per-key rate limit (`GUARD_RATE_LIMIT_PER_MINUTE`, or the key's own limit); see `Retry-After` |
| 503 | No guardrail snapshot is loaded (fail-closed) |

Ops endpoints: `GET /health`, `GET /ready`, `GET /version`, `GET /metrics` (Prometheus).

**Proxy mode** (`PROXY_ENABLED=true`): `POST /v1/chat/completions` is OpenAI-compatible. Point an
OpenAI client at the gateway with a gateway key. The input stage checks the messages, then the
gateway calls the provider with its own key, and the output and tool stages check the answer and
any tool calls. Blocked or held requests get 403 with an OpenAI-style error (`guardrail_blocked`,
`guardrail_escalated`). Streaming and non-text content are refused (fail-closed). See
[docs/agent-integration.md](docs/agent-integration.md#proxy-mode-no-code-changes).

## Scoring (separate agent and action scores)

- `trust_score` is the agent's base trust from `guardrail.agent_profiles`. An unknown agent gets 0.
- `risk_score` is `min(100, action base risk + classification modifier + environment modifier)`,
  using `guardrail.action_catalog` and `guardrail.score_modifiers`. An unknown action gets 100.
- Both scores go to OPA. The starter policy denies trust below 50 or risk above 70 in
  production, delegation chains deeper than 3, and tools not on the agent's list. It also
  requires `ai-gateway-pii` on input, retrieval, tool and output for `PII` or `CONFIDENTIAL` data.

Manage the catalog through the control plane (`/cp/v1/tenants/...`). Changes reach gateways within
seconds. With `CONFIG_SOURCE=file`, use `python -m app.cli` in the gateway instead.

## Engine rules

- Guardrails run in `order`. Consecutive assignments that share a `parallel_group` run concurrently.
- Precedence is **BLOCK > ESCALATE > MODIFY > ALLOW**. MODIFY passes the changed payload to the
  next guardrail, and BLOCK stops the stage.
- Errors and time-outs follow `failure_mode`. **`fail_closed` (BLOCK) is used in every
  environment**, so failures show up during testing too.
- `shadow` assignments run and are audited but never change the outcome.
- ESCALATE holds the payload in the control plane's review queue and returns 202. Approval releases
  it. Rejection, expiry (15 min) or an unreachable queue results in BLOCK. With `CONFIG_SOURCE=file`
  there is no queue, so ESCALATE is returned as BLOCK. Reviewers decide in the console's review queue.
- OPA obligations are only satisfied by **enforced** guardrails. While production runs
  `ai-gateway-pii` in shadow mode, requests marked `PII` or `CONFIDENTIAL` are blocked on
  input, retrieval, tool and output. Switch the assignment to `enforce` once the shadow review is done.

## Audit

`audit.audit_events` is partitioned by month and kept for 12 months (`AUDIT_RETENTION_MONTHS`).
A trigger blocks UPDATE and DELETE, so the table is append-only. Each row stores decisions,
reasons, scores, finding types and offsets, and a SHA-256 hash of the payload. **Raw payload
text is never stored.** If Postgres can't take writes, events go to a disk spool on the gateway
(`AUDIT_SPOOL_DIR`) and are replayed when it recovers. On Kubernetes a CronJob runs partition
maintenance instead of the gateway (`AUDIT_MAINTENANCE=false`).

## Tests

```bash
pip install -e "packages/guardrail-sdk[test]" -r services/guardrail-gateway/requirements-dev.txt
pytest packages/guardrail-sdk
pytest tests/e2e                                   # add GUARDRAIL_E2E_URL/KEY for the live cases
cd services/guardrail-gateway && POSTGRES_TEST_DSN=postgresql+asyncpg://gateway:gateway@localhost/gateway_test pytest
cd services/guardrail-control-plane && pip install -r requirements-dev.txt && \
  POSTGRES_TEST_DSN=postgresql+asyncpg://gateway:gateway@localhost/cp_test pytest   # every flow on memory + Postgres
pytest tests/e2e/test_control_plane.py           # live: CONTROL_PLANE_E2E_URL, CP_E2E_ADMIN_KEY
opa test policies
cd apps/console && npm install && npm run typecheck && npm test && npm run build && npm run e2e   # console
helm lint deploy/helm/guardrail-platform --set secrets.create=true                                  # chart
# ai-gateway with real Presidio (needs en_core_web_lg):
cd services/ai-gateway/instant-redaction-service && pip install -r requirements-dev.txt && pytest
```

## Deployment (k3s)

[docs/deployment.md](docs/deployment.md) walks through images, SOPS secrets, the Helm install,
multiple environments, mTLS (Linkerd or app-level), monitoring and sizing for a 3-node k3s
cluster. Everything is configured through environment variables; the chart maps its values onto them.
