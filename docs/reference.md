# Reference

Details behind the [README](../README.md): the gateway API, how decisions are made, scoring,
audit, tests and the repository layout.

## Local stack (Docker Compose)

```bash
docker compose up --build
docker compose exec guardrail-gateway cat /bootstrap/dev.env          # DEMO_GATEWAY_API_KEY=gk_...
docker compose exec guardrail-control-plane cat /bootstrap/cp.env     # CP_ADMIN_KEY, CP_APPROVER_KEY
docker compose -f docker-compose.yml -f docker-compose.mtls.yml up --build   # with mTLS between services
```

The one-shot `guardrail-bootstrap` container runs the migrations, seeds a `demo` tenant (agents,
action catalog, score modifiers), and creates a redaction project and service key in ai-gateway's
project-service. It writes the generated keys to the `bootstrap` volume, where the gateway reads
them at start-up.

The gateway runs with `CONFIG_SOURCE=control_plane`. On the first run the control plane imports
the seeded tenant and `config/snapshots/*.json`, and after that the control plane is the source of
truth: change guardrails, keys and scores in the console or its API, not in the snapshot files.

With the dev snapshot, the AI Gateway guardrail (`ai-gateway-pii`) redacts an email and employee
ID on input (`modify`) and blocks a US SSN. On the retrieval stage, chunks with an SSN or card number are dropped. On the
tool stage, PII sent to `http.*`, `email.*`, `slack.*` or `webhook.*` tools is blocked, and PII in
tool results is redacted. Every guardrail and its settings: [guardrails.md](guardrails.md).

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
[agent-integration.md](agent-integration.md#proxy-mode-no-code-changes).

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


## Repository layout

```text
packages/guardrail-sdk/           contracts, Guardrail base class, manifest, conformance + evaluation, agent client and hooks
  guardrail_sdk/integrations/     guard_tool, LangGraph nodes/retriever, CrewAI tool/inputs/output
services/guardrail-gateway/       :8100  gateway + context builder + OPA client + engine + audit
  app/plugins/ai_gateway_pii/     AI Gateway PII guardrail: 1.0.0 (input/output), 1.1.0 (all four stages)
  app/plugins/noop/               reference local guardrail / template
  config/snapshots/<env>.json     which guardrails run where with CONFIG_SOURCE=file (seed for the control plane)
  alembic/                        guardrail + audit schemas (own version table in `guardrail`)
services/guardrail-control-plane/ :8200  registry, snapshots, catalog, review queue, RBAC (schema `control`), serves /console
apps/console/                     operator console + human review UI (React, TypeScript, Vite); mock control plane + Playwright smoke test
deploy/helm/guardrail-platform/   k3s/Kubernetes chart (values-k3s.yaml, values-cloud.yaml), alerts, Grafana dashboard
deploy/secrets/                   SOPS + age setup and the Secret template
services/ai-gateway/              the AI Gateway: existing PII redaction platform (project-service :8000, instant-redaction :8001)
policies/guardrails/              Rego authorization policy + tests
examples/sample_agent/            framework-free agent using all four stages
eval/                             labelled PII dataset (880 cases) + generator + eval config
tests/e2e/                        sample agent against a fake gateway and the live stack
docs/                             guardrail catalog, agent integration, adding guardrails, control plane, deployment, runbooks, security
```

