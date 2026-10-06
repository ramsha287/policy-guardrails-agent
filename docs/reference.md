# Reference: APIs, configuration, CLI, layout

## Gateway API

Agent calls authenticate with `X-API-Key: gk_…` (proxy mode also accepts `Authorization: Bearer gk_…`).

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/guard/{stage}` | The decision. `stage`: `input`, `retrieval`, `tool`, `output` (`agent` is accepted but nothing is assigned to it by default). Status codes: [agent-integration.md](agent-integration.md#what-the-agent-gets-back) |
| `GET /v1/escalations/{id}` | A held request's status: `escalate` (pending), `allow` + payload (approved), `block` (rejected/expired). Needs `CONFIG_SOURCE=control_plane` |
| `GET /v1/verifications/{id}` | A user confirmation's status |
| `POST /v1/verifications/{id}/confirm` | `{"approve": bool}` with `Authorization: Bearer <user's IdP token>`. 403 wrong user / stale sign-in / nonce, 404, 409 already decided |
| `POST /v1/chat/completions` | OpenAI-compatible proxy, only with `PROXY_ENABLED=true` ([agent-integration.md](agent-integration.md#proxy-mode-no-code-changes)) |
| `POST /access/v1/evaluation`, `POST /access/v1/evaluations` | OpenID AuthZEN 1.0 ([decisions.md](decisions.md#authzen-api)) |
| `GET /.well-known/authzen-configuration` | AuthZEN metadata (no key) |
| `POST /internal/simulate` | Control plane only (`X-Internal-Token`): dry-run a snapshot |
| `GET /health`, `GET /ready`, `GET /version`, `GET /metrics` | Ops. `/ready` checks the snapshot, database, OPA, Redis and (control-plane mode) the catalog. `/metrics` has no auth: keep it inside the cluster |

## Control plane API

`X-Admin-Key: cpk_…`. Permissions are checked per tenant; tenant keys only see their tenant.
Errors are `{"error": …}` (422 adds `errors` and `warnings`).

| Area | Endpoints | Permission |
| --- | --- | --- |
| Identity | `GET /cp/v1/me` (roles, permissions, environments, features) | any key |
| Tenants | `POST/GET /cp/v1/tenants`, `PATCH /cp/v1/tenants/{t}` (`status`), `PUT /cp/v1/tenants/{t}/advisor-policy` | `catalog:write` (create/suspend: platform keys) |
| Gateway keys | `POST/GET /cp/v1/tenants/{t}/api-keys`, `PATCH …/api-keys/{id}` (`agent_id`, `rate_limit_per_minute`), `DELETE …/api-keys/{id}` (revoke) | `catalog:write` / read. The raw key is returned once |
| Agents, actions, modifiers | `PUT/GET/DELETE /cp/v1/tenants/{t}/agents[/{a}]`, `…/actions[/{id}]`, `…/modifiers[/{id}]`; `GET /cp/v1/catalog/current` | `catalog:write` / read |
| Registry | `POST /cp/v1/guardrails/versions` (`manifest` or `manifest_yaml`), `GET /cp/v1/guardrails`, `POST /cp/v1/guardrails/{id}/versions/{v}/deprecate` | `registry:write` (platform) / read |
| Assignments | `GET /cp/v1/environments/{env}/assignments`, `PUT/PATCH/DELETE …/assignments/{id}`, `GET …/diff` | `assignments:write` (global scope: platform) / read |
| Publish | `POST /cp/v1/environments/{env}/publish` (`note`, `force`), `POST …/rollback` (`version`), `GET …/snapshots`, `GET …/snapshots/current`, `GET …/snapshots/{version}` | `publish:request` (platform) / read. Tenant keys see global and own-tenant assignments only |
| Approvals | `GET /cp/v1/publish-requests`, `POST /cp/v1/publish-requests/{id}/approve|reject` | `publish:approve` (platform, not the requester) |
| Reviews | `GET /cp/v1/reviews?status=&tenant_id=`, `GET /cp/v1/reviews/{id}[?include_raw=true]`, `POST …/approve|reject` (`note`) | read / `reviews:raw` / `reviews:decide` |
| Simulate | `POST /cp/v1/simulate` (`environment`, `source` working/current, `tenant_id`, `stage`, `request`) | read on the tenant |
| Playground | `POST /cp/v1/playground` (`environment`, `stage`, `gateway_key`, `request`) → the gateway's status and body; `POST /cp/v1/playground/escalations/{id}` (`environment`, `gateway_key`) | `catalog:write` on the key's tenant; environment in `PLAYGROUND_ENVIRONMENTS` |
| Decision log | `GET /cp/v1/decisions?environment=&tenant_id=&hours=&limit=&agent_id=&stage=&decision=&outcome=&session_id=`, `GET /cp/v1/decisions/{request_id}` | read; needs `AUDIT_DSN` (503 otherwise) |
| Analytics | `GET /cp/v1/analytics/guardrails?environment=&tenant_id=&hours=`, `GET /cp/v1/analytics/advisors?…` | read; needs `AUDIT_DSN` |
| Fleet, history, people | `GET /cp/v1/environments/{env}/gateways`, `GET /cp/v1/changes?entity=&entity_id=&limit=` (platform), `POST/GET/DELETE /cp/v1/admin-keys[/{id}]` | read / platform / `admin-keys:write` |
| Discovery and inventory | `/inv/v1/…`: connectors, runs, entities, graph, link/register/ignore, coverage, summary, findings, reconcile | [discovery.md](discovery.md#api) |
| Gateway-facing | `GET /cp/v1/internal/environments/{env}/snapshot`, `GET /cp/v1/internal/catalog` (ETags), `POST /cp/v1/internal/gateways/heartbeat`, `POST /cp/v1/internal/reviews`, `GET /cp/v1/internal/reviews/{id}` | `X-Internal-Token` |
| Ops | `GET /health`, `/ready`, `/version`, `/metrics`; `/console`, `/` and `/review` redirect to the console | none |

A curl walkthrough of the catalog, registry, assignments and publishing:

```bash
CP=localhost:8200/cp/v1; A="X-Admin-Key: $CP_ADMIN_KEY"; B="X-Admin-Key: $CP_APPROVER_KEY"; J='content-type: application/json'
curl -s -XPOST $CP/tenants -H "$A" -H "$J" -d '{"id":"acme","name":"Acme"}'
curl -s -XPUT $CP/tenants/acme/agents/support-bot -H "$A" -H "$J" -d '{"base_trust_score":80,"allowed_tools":["search.*","crm.read"]}'
curl -s -XPOST $CP/tenants/acme/api-keys -H "$A" -H "$J" -d '{"name":"support-bot","agent_id":"support-bot","environments":["dev","staging"]}'
curl -s -XPUT $CP/tenants/acme/actions -H "$A" -H "$J" -d '{"action":"crm.read","resource_pattern":"*","base_risk_score":30}'
curl -s -XPUT $CP/environments/staging/assignments/global-secrets -H "$A" -H "$J" -d '{
  "guardrail_id":"secrets","guardrail_version":"1.0.0","scope_type":"global","stages":["input","output"],"order":20,"mode":"shadow"}'
curl -s -XPATCH $CP/environments/staging/assignments/global-secrets -H "$A" -H "$J" -d '{"mode":"enforce"}'
curl -s $CP/environments/staging/diff -H "$A"
curl -s -XPOST $CP/environments/staging/publish -H "$A" -H "$J" -d '{"note":"enforce secrets"}'
curl -s -XPOST $CP/environments/production/publish -H "$A" -H "$J" -d '{"note":"..."}'          # -> pending_approval
curl -s -XPOST $CP/publish-requests/$REQ/approve -H "$B" -H "$J" -d '{"note":"looks good"}'      # a different admin
curl -s -XPOST $CP/environments/production/rollback -H "$A" -H "$J" -d '{"version":"production-00011-9b1e04aa"}'
```

Publishing validates everything first: the version exists and isn't deprecated, every stage is
supported, `parallel_group` members are `parallel_safe`, `config` matches the manifest's schema, and
the version is installed on the environment's live gateways (`"force": true` turns the last two
into warnings). Identical content returns `"status": "unchanged"`. A production request becomes
`stale` if another version is published first and expires after `PUBLISH_REQUEST_TTL_HOURS`.
Rollback publishes a *new* version with the old content and resets the working set to it.

## Gateway configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `GATEWAY_ENV` | `dev` | `dev`, `staging` or `production`: the environment this gateway serves |
| `POSTGRES_DSN` | required | Schemas `guardrail` and `audit` |
| `OPA_URL`, `OPA_DECISION_PATH`, `OPA_TIMEOUT_MS` | `http://opa:8181`, `/v1/data/guardrails/authz/decision`, 300 | Policy (fails closed) |
| `CONFIG_SOURCE` | `file` (Compose/Helm: `control_plane`) | `control_plane` = snapshot + catalog from the control plane; `file` = `SNAPSHOT_PATH` + own tables, no review queue |
| `CONTROL_PLANE_URL`, `INTERNAL_TOKEN` | — | Control plane and the shared token |
| `CACHE_DIR`, `CP_POLL_SECONDS`, `HEARTBEAT_SECONDS` | `/var/cache/guardrail-gateway`, 30, 30 | Last good config on disk; poll and heartbeat intervals |
| `SNAPSHOT_PATH`, `SNAPSHOT_RELOAD_SECONDS`, `PLUGIN_DIRS` | `config/snapshots/dev.json`, 30, `[app/plugins]` | File mode and plugin locations |
| `DEFAULT_GUARDRAIL_TIMEOUT_MS` | 1000 (Helm 800) | When neither manifest nor assignment sets one |
| `HTTP_TIMEOUT_SECONDS`, `MAX_BODY_BYTES` | 5.0, 1048576 | Outbound timeout; request body limit (413) |
| `AUTH_CACHE_TTL_SECONDS`, `CATALOG_CACHE_TTL_SECONDS` | 30, 30 | File-mode caches (control-plane mode uses 5 s / 2 s) |
| `GUARD_RATE_LIMIT_PER_MINUTE` | 0 (unlimited) | Per key, **per replica**; the chart divides the global value by replicas (per-key overrides are not divided) |
| `RISK_MODE` | `shadow` | `off`, `shadow`, `enforce` ([decisions.md](decisions.md#risk_mode)) |
| `REQUIRE_BOUND_KEYS` | `false` | Refuse keys not bound to an agent (`UNBOUND_KEY`) |
| `INTERNAL_DOMAINS` | empty | Comma-separated internal domain suffixes (private IPs, `*.svc`, `*.cluster.local`, single-label hosts always count) |
| `RISK_CONFIG_JSON` | `{}` | Weight and limit overrides (`RiskConfig` in `app/risk/engine.py`) |
| `SESSION_MEMORY_ENTRIES` | 50000 | In-memory session store size when there is no Redis |
| `REDIS_URL` | — | Session state, config push, Redis events |
| `ADVISORS_JSON` | empty (Compose: local advisor in shadow) | [decisions.md](decisions.md#advisors); credentials in `ADVISOR_SECRET_*` |
| `VERIFICATION_ENABLED` | `true` | `false` sends every `verify` to human review |
| `VERIFY_OIDC_ISSUER`, `VERIFY_OIDC_AUDIENCE`, `VERIFY_OIDC_JWKS_URL` / `VERIFY_OIDC_JWKS_JSON` | — | IdP for user confirmation |
| `VERIFY_USER_CLAIM`, `VERIFY_MAX_AUTH_AGE_SECONDS`, `VERIFY_REQUIRED_ACR`, `VERIFY_REQUIRE_NONCE` | `sub`, 600, empty, `true` | Token checks |
| `VERIFY_DEV_SECRET` | — | Dev only (refused unless `GATEWAY_ENV=dev`, ≥ 32 chars) |
| `VERIFY_SQL_DRY_RUN`, `VERIFY_DRY_RUN_MAX_ROWS` | —, 10000 | JSON `{"tool or resource": "postgresql://read-replica"}`; max planner estimate |
| `OUTBOX_SINKS`, `OUTBOX_WEBHOOK_URL`, `OUTBOX_WEBHOOK_SECRET`, `OUTBOX_RETENTION_DAYS`, `OUTBOX_CHAIN_HEADS_SECONDS` | empty, —, —, 7, 3600 | Decision events ([decisions.md](decisions.md#decision-events)) |
| `AUDIT_QUEUE_SIZE`, `AUDIT_BATCH_SIZE`, `AUDIT_FLUSH_SECONDS` | 10000, 200, 1.0 | Asynchronous audit writer |
| `AUDIT_RETENTION_MONTHS`, `AUDIT_MAINTENANCE` | 12, `true` (Helm: `false`, a CronJob does it) | Partitions |
| `AUDIT_SPOOL_DIR`, `AUDIT_SPOOL_MAX_MB` | `/var/cache/guardrail-gateway/audit-spool`, 512 | Disk spool while Postgres is down (`""` disables) |
| `PROXY_ENABLED`, `PROXY_UPSTREAM_URL`, `PROXY_UPSTREAM_API_KEY`, `PROXY_DEFAULT_AGENT_ID`, `PROXY_MODELS`, `PROXY_TIMEOUT_SECONDS` | `false`, OpenAI, —, `proxy`, any, 120 | Proxy mode |
| `AI_GATEWAY_URL`, `AI_GATEWAY_PROJECT_ID`, `AI_GATEWAY_API_KEY` | `http://instant-redaction-service:8001`, —, — | `ai-gateway-pii` (`${…}` in snapshot config; `env://` in the manifest) |
| `MODERATION_BASE_URL`, `MODERATION_API_KEY` | OpenAI, — | `content-moderation` (operator-set, not assignment config) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | Tracing |
| `BOOTSTRAP_ENV_FILE` | — | Dev: load the bootstrap env file without overriding |
| `PORT`, `HOST`, `INTERNAL_PORT` | 8100, `0.0.0.0`, — | With `INTERNAL_PORT`, `/internal/*` is only served there |
| `TLS_CERT_FILE`, `TLS_KEY_FILE`, `TLS_CLIENT_CA_FILE`, `TLS_PUBLIC`, `TLS_CA_FILE`, `TLS_CLIENT_CERT_FILE`, `TLS_CLIENT_KEY_FILE` | — | mTLS without a mesh ([operations.md](operations.md#mtls-between-services)) |
| `LOG_LEVEL` | `INFO` | |

## Control plane configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `POSTGRES_DSN` | required | Schemas `control` and `inventory` |
| `INTERNAL_TOKEN` | required (≥ 16 chars) | Shared with gateways |
| `REDIS_URL` | — | Publish config and inventory events (gateways still poll without it) |
| `REVIEW_ENCRYPTION_KEY` | ephemeral (warns) | Fernet key for held payloads. Set it outside dev, or pending reviews are unreadable after a restart |
| `TWO_PERSON_ENVIRONMENTS` | `["production"]` | Environments that need a second admin |
| `PUBLISH_REQUEST_TTL_HOURS`, `REVIEW_TTL_MINUTES`, `GATEWAY_STALE_SECONDS` | 24, 15, 300 | Expiry |
| `GATEWAY_URL`, `GATEWAY_URLS` | — | Gateway for `/simulate` (default, and per environment as a JSON map) |
| `PLAYGROUND_ENVIRONMENTS`, `PLAYGROUND_GATEWAY_URLS` | `[]` (Compose: `["dev"]`), `{}` | Environments where the Playground may send real requests, and the gateways' *public* URLs (fallback: `GATEWAY_URLS`/`GATEWAY_URL`) |
| `AUDIT_DSN` | — | Audit read access: Analytics, Advisors, Decision log, the `gateway` connector, advisor labels. Use a read-only user |
| `HTTP_TIMEOUT_SECONDS` | 10 | Outbound calls to gateways |
| `DISCOVERY_SCHEDULER`, `DISCOVERY_TICK_SECONDS`, `DISCOVERY_MAX_OBSERVATIONS`, `DISCOVERY_ALLOW_HTTP`, `DISCOVERY_LOG_DIR`, `DISCOVERY_SECRET_*` | `true`, 60, 20000, `false`, `/var/lib/guardrail-discovery/logs`, — | [discovery.md](discovery.md#settings) |
| `CONSOLE_DIR` | `/app/console` | Built console, served at `/console` when present |
| `PORT`, `HOST`, `INTERNAL_PORT`, `TLS_*` | 8200, `0.0.0.0`, —, — | As for the gateway; `/cp/v1/internal/*` only on `INTERNAL_PORT` when set |
| `LOG_LEVEL` | `INFO` | |

Helm values map onto these; the chart's README lists them
([deploy/helm/guardrail-platform/README.md](../deploy/helm/guardrail-platform/README.md)).

## CLI

| Service | Command | Does |
| --- | --- | --- |
| gateway | `python -m app.cli bootstrap-dev --write FILE` | Dev seed: `demo` tenant, unbound key, agents, actions, modifiers, AI Gateway project + service key |
| gateway | `python -m app.cli ai-gateway-credentials --project-service-url URL` | Create the redaction project and service key (Helm installs) |
| gateway | `python -m app.cli verify-audit-chain --days N [--tenant T]` | Check the audit hash chains (exit 1 on problems) |
| gateway | `python -m app.cli dev-user-token --user U [--verification ID]` | Dev only: a user token for confirmations |
| gateway | `python -m app.cli create-tenant / create-api-key / upsert-agent / upsert-action / upsert-modifier / partitions` | File-mode catalog tables; audit partitions |
| gateway | `python -m app.bench …`, `python -m app.advise.calibrate …` | Latency benchmark; advisor calibration ([testing.md](testing.md#gate-1)) |
| control plane | `python -m app.cli create-admin-key --name N [--roles R] [--tenant T]` | First admin key, or recovery |
| control plane | `python -m app.cli bootstrap-dev …`, `import-gateway --snapshot … --plugin-dir …` | Import the gateway's tables and snapshot files once |
| control plane | `python -m app.cli discovery-sync [--tenant] [--connector]`, `discovery-reconcile [--tenant]` | Run connectors / reconcile (exit 1 if a run failed) |
| control plane | `python -m app.cli advisor-training-set --out FILE [--days] [--tenant] [--include-released]` | Labels for advisor calibration |
| control plane | `python -m app.cli dev-certs --out DIR --names …` | A private CA and service certificates for mTLS labs |

## Repository layout

```text
packages/guardrail-sdk/           contracts, Guardrail base class, manifest, conformance + evaluation, agent client and hooks
  guardrail_sdk/integrations/     guard_tool, LangGraph nodes/retriever, CrewAI tool/inputs/output
services/guardrail-gateway/       :8100 gateway: flow, context, descriptors, sessions, risk, OPA client, engine, advisors, verification, audit, events
  app/plugins/                    ai_gateway_pii (1.0.0, 1.1.0), secrets, prompt_injection, topic_limits, content_moderation, noop
  config/snapshots/<env>.json     seed snapshots (and the config for CONFIG_SOURCE=file)
services/guardrail-control-plane/ :8200 catalog, registry, publishing, reviews, RBAC, discovery/inventory, analytics, decision log, playground; serves /console
apps/console/                     the console (React, TypeScript, Vite); mock control plane + Playwright smoke test
services/ai-gateway/              the AI Gateway: project-service :8000, instant-redaction-service :8001 (Presidio)
policies/guardrails/              Rego policy + tests
deploy/helm/guardrail-platform/   Helm chart, alerts, Grafana dashboard
deploy/secrets/                   SOPS + age setup and the Secret template
examples/                         sample agent; discovery demo (MCP server, DNS log generator)
eval/                             labelled PII set, secrets set generator, eval config
tests/e2e/                        sample agent, control-plane changes and security flows against the live stack
docs/                             this documentation
```
