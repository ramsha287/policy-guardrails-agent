# Custom Guardrail Platform for AI Agents

Plug-in guardrails for AI agents with no NeMo dependency. Every request goes through
**Security Gateway → Context Builder → Policy Engine (OPA) → Guardrail Engine → Agent**.
Every decision is written to an append-only audit log.

The first guardrail is the existing **AI Security Gateway** (Presidio PII redaction). It is
plugged in over HTTP as `ai-gateway-pii`.

This branch delivers **phases 0–2** of the build plan:

| Phase | Status | What's in it |
| --- | --- | --- |
| 0. Foundations | Done | Monorepo, `guardrail-sdk`, CI, Docker Compose with Postgres, Redis and OPA |
| 1. Gateway + engine core | Done | `/v1/guard/{stage}`, auth, normalization, context and scoring, OPA with Rego, pipeline, audit |
| 2. ai-gateway adapter | Done | `ai-gateway-pii@1.0.0` for input and output; ai-gateway changes 1, 4, 6, 7, 10 |
| 3. Retrieval + tool stages | Next | ai-gateway `/text/batch`, `/json`, project cache; agent SDK hooks |
| 4. Control plane | Planned | Registry API, snapshots, versioning, review queue, RBAC |
| 5. Hardening | Planned | mTLS, SOPS, dashboards, review UI, k3s Helm charts |

## Repository layout

```text
packages/guardrail-sdk/           contracts, Guardrail base class, manifest, conformance suite, agent client
services/guardrail-gateway/       :8100  gateway + context builder + OPA client + engine + audit
  app/plugins/ai_gateway_pii/     first guardrail (remote adapter to instant-redaction-service)
  app/plugins/noop/               reference local guardrail / template
  config/snapshots/<env>.json     which guardrails run where (control plane replaces this in phase 4)
  alembic/                        guardrail + audit schemas (own version table in `guardrail`)
services/ai-gateway/              existing PII redaction platform (project-service :8000, instant-redaction :8001)
policies/guardrails/              Rego authorization policy + tests
docs/                             ai-gateway change spec, guide to adding guardrails
```

## Run it

```bash
docker compose up --build
docker compose exec guardrail-gateway cat /bootstrap/dev.env   # DEMO_GATEWAY_API_KEY=gk_...
```

The one-shot `guardrail-bootstrap` container does three things. It runs the migrations, and
it seeds a `demo` tenant with agents, an action catalog and score modifiers. It also creates
a redaction project and a service API key in ai-gateway's project-service. It writes the
generated keys to the `bootstrap` volume, and the gateway reads them from there at start-up.

```bash
KEY=gk_...   # from dev.env
curl -s localhost:8100/v1/guard/input -H "X-API-Key: $KEY" -H 'content-type: application/json' -d '{
  "agent_id": "research-agent", "action": "llm.chat", "user_id": "u1",
  "data_classification": "PII",
  "payload": {"text": "Email jane.doe@example.com about invoice EMP-123456"}
}' | jq '{decision, reason, text: .payload.text, trust_score, risk_score}'
```

With the dev snapshot you get `decision: "modify"`, and the email and employee ID come back
redacted. A US SSN on input returns `block`.

## From an agent

```python
from guardrail_sdk.client import GuardClient

async with GuardClient("http://guardrail-gateway:8100", api_key, agent_id="research-agent") as guard:
    r = await guard.check_input(user_text, user_id=user_id, data_classification="PII")
    if not r.allowed:
        return f"Request blocked: {r.reason}"
    answer = await llm(r.payload.text)
    out = await guard.check_output(answer, user_id=user_id, data_classification="PII")
    return out.payload.text if out.allowed else "Sorry, I can't share that."
```

## API

`POST /v1/guard/{stage}` where `stage` is `input`, `retrieval`, `tool`, `output` or `agent`.
Authenticate with the `X-API-Key` header. The tenant comes from the key, and the environment
comes from the gateway's configuration.

| Status | Meaning |
| --- | --- |
| 200 | `decision` is `allow`, `modify` (use the returned `payload`) or `block` (a guardrail blocked) |
| 403 | `decision` is `block` because OPA denied the request (`policy.reason`) |
| 401 / 422 / 413 | Bad key / invalid body / body over 1 MB |
| 503 | No guardrail snapshot is loaded (fail-closed) |

Ops endpoints: `GET /health`, `GET /ready`, `GET /version`, `GET /metrics` (Prometheus).

## Scoring (separate agent and action scores)

- `trust_score` is the agent's base trust from `guardrail.agent_profiles`. An unknown agent gets 0.
- `risk_score` is `min(100, action base risk + classification modifier + environment modifier)`,
  using `guardrail.action_catalog` and `guardrail.score_modifiers`. An unknown action gets 100.
- Both scores go to OPA. The starter policy denies trust below 50 or risk above 70 in
  production, delegation chains deeper than 3, and tools not on the agent's list. It also
  requires `ai-gateway-pii` on input and output for `PII` or `CONFIDENTIAL` data.

Manage the catalog with `python -m app.cli` (see `services/guardrail-gateway/app/cli.py`) until the control plane ships.

## Engine rules

- Guardrails run in `order`. Consecutive assignments that share a `parallel_group` run concurrently.
- Precedence is **BLOCK > ESCALATE > MODIFY > ALLOW**. MODIFY passes the changed payload to the
  next guardrail, and BLOCK stops the stage.
- Errors and time-outs follow `failure_mode`. **`fail_closed` (BLOCK) is used in every
  environment**, so failures show up during testing too.
- `shadow` assignments run and are audited but never change the outcome.
- ESCALATE is returned as BLOCK until the human review queue ships.
- OPA obligations are only satisfied by **enforced** guardrails. While production runs
  `ai-gateway-pii` in shadow mode, requests marked `PII` or `CONFIDENTIAL` are blocked on
  input and output. Switch the assignment to `enforce` once the shadow review is done.

## Audit

`audit.audit_events` is partitioned by month and kept for 12 months (`AUDIT_RETENTION_MONTHS`).
A trigger blocks UPDATE and DELETE, so the table is append-only. Each row stores decisions,
reasons, scores, finding types and offsets, and a SHA-256 hash of the payload. **Raw payload
text is never stored.**

## Tests

```bash
pip install -e "packages/guardrail-sdk[test]" -r services/guardrail-gateway/requirements-dev.txt
pytest packages/guardrail-sdk
cd services/guardrail-gateway && POSTGRES_TEST_DSN=postgresql+asyncpg://gateway:gateway@localhost/gateway_test pytest
opa test policies
```

## Deployment notes (k3s)

Images are plain multi-arch Python builds, and configuration comes only from environment
variables. The gateway is stateless apart from the snapshot file or ConfigMap. On Kubernetes
or k3s, run `alembic upgrade head` as a Job, mount the snapshot as a ConfigMap and run OPA as
a sidecar. Helm charts are part of phase 5.
