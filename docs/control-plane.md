# Control plane

`services/guardrail-control-plane` (port 8200) is the source of truth for **which guardrails run
where** and for the **tenant catalog**. Gateways pull from it, so a change needs no redeploy.

| Document | What it holds | How it is published |
| --- | --- | --- |
| Snapshot (one per environment) | Guardrail assignments: version, scope, stages, order, parallel group, mode, failure mode, config | Compiled from the environment's working set on `publish`. Two-person approval in `TWO_PERSON_ENVIRONMENTS` (default `production`) |
| Catalog (one, all tenants) | Tenants, gateway API-key **hashes**, agents (base trust), actions (base risk), score modifiers | Automatically on every catalog change |

Both documents are immutable and versioned. Snapshot versions look like `production-00012-3fa9c2d1`
(environment, per-environment sequence, content hash).

Most of what follows can also be done in the **console** at `http://<control-plane>/console/`
([apps/console](../apps/console/README.md)). It uses this API, with the same roles.

## How gateways stay in sync

Set `CONFIG_SOURCE=control_plane`, `CONTROL_PLANE_URL` and `INTERNAL_TOKEN` on the gateway. With
`CONFIG_SOURCE=file` (the default) it keeps using `config/snapshots/<env>.json` and its own tables,
as in phases 1–3.

- The gateway fetches `/cp/v1/internal/environments/{env}/snapshot` and `/cp/v1/internal/catalog`
  with ETags every `CP_POLL_SECONDS` (default 30). It also refreshes right away when Redis announces
  a publish on `guardrail:snapshot.published` or `guardrail:catalog.published`. Key revocations
  apply within a few seconds.
- Every accepted document is written to `CACHE_DIR`. If the control plane is down at start-up, the
  gateway serves the last cached copies. With neither, it stays not-ready and refuses requests
  (fail-closed).
- A snapshot that fails to compile on the gateway (for example, a `${VAR}` it lacks) is rejected,
  and the gateway keeps the previous one. The error shows on `/ready` and in the heartbeat.
- Every `HEARTBEAT_SECONDS` the gateway reports its installed guardrail manifests, live versions
  and last error. `publish` checks that every assigned guardrail version is installed on the
  environment's live gateways. Pass `"force": true` to turn that check into a warning.

## Authentication and roles

Call the API with `X-Admin-Key: cpk_...`. Admin keys are separate from gateway API keys.
`GET /cp/v1/me` returns the key's roles, tenant and permissions (the console uses it to show only
what the key can do).

| Role | Can |
| --- | --- |
| `viewer` | Read everything in its scope |
| `reviewer` | Plus approve or reject held requests (sees a redacted preview only) |
| `reviewer-raw` | Plus read the held payload (`?include_raw=true`) |
| `editor` | Plus change the catalog and assignments, and request a publish |
| `admin` | Everything, including the guardrail registry, publish approval and admin keys |

A key with `tenant_id` set is a **tenant key**. It only sees and changes its own tenant's catalog,
tenant- and agent-scoped assignments and review queue. The registry, publishing and the change log
are **platform only**, because a snapshot covers every tenant in an environment.

```bash
docker compose exec guardrail-control-plane cat /bootstrap/cp.env   # CP_ADMIN_KEY, CP_APPROVER_KEY
python -m app.cli create-admin-key --name alice --roles editor
python -m app.cli create-admin-key --name acme-reviewer --roles reviewer --tenant acme
```

## Walkthrough

```bash
CP=localhost:8200/cp/v1; A="X-Admin-Key: $CP_ADMIN_KEY"; B="X-Admin-Key: $CP_APPROVER_KEY"
J='content-type: application/json'
```

**Catalog** (published to gateways immediately):

```bash
curl -s -XPOST $CP/tenants -H "$A" -H "$J" -d '{"id":"acme","name":"Acme"}'
curl -s -XPOST $CP/tenants/acme/api-keys -H "$A" -H "$J" \
  -d '{"name":"support-bot","environments":["dev","staging"]}'   # returns the raw key once
curl -s -XPUT $CP/tenants/acme/agents/support-bot -H "$A" -H "$J" \
  -d '{"base_trust_score":80,"allowed_tools":["search.*","crm.read"]}'
curl -s -XPUT $CP/tenants/acme/actions -H "$A" -H "$J" \
  -d '{"action":"crm.read","resource_pattern":"*","base_risk_score":30}'
curl -s -XPUT $CP/tenants/acme/modifiers -H "$A" -H "$J" -d '{"kind":"classification","value":"PII","delta":20}'
curl -s -XPATCH $CP/tenants/acme/api-keys/$KEY_ID -H "$A" -H "$J" -d '{"rate_limit_per_minute":120}'  # null = default, 0 = unlimited
curl -s -XDELETE $CP/tenants/acme/api-keys/$KEY_ID -H "$A"              # revoke
curl -s -XPATCH $CP/tenants/acme -H "$A" -H "$J" -d '{"status":"suspended"}'  # every key stops working
```

**Registry.** Register a guardrail version with its manifest (`manifest` as JSON, or the
`guardrail.yaml` text as `manifest_yaml`) and, optionally, its conformance report:

```bash
python -c 'import json,sys;print(json.dumps({"manifest_yaml": open("guardrail.yaml").read()}))' \
  | curl -s -XPOST $CP/guardrails/versions -H "$A" -H "$J" -d @-
curl -s -XPOST $CP/guardrails/prompt-injection/versions/0.9.0/deprecate -H "$A"
```

**Assignments.** Edit the working set, then diff and publish it:

```bash
curl -s -XPUT $CP/environments/staging/assignments/global-prompt-injection -H "$A" -H "$J" -d '{
  "guardrail_id":"prompt-injection","guardrail_version":"1.0.0","scope_type":"global",
  "stages":["input"],"order":5,"mode":"shadow","config":{"threshold":0.8}}'
curl -s -XPATCH $CP/environments/staging/assignments/global-prompt-injection -H "$A" -H "$J" -d '{"mode":"enforce"}'
curl -s $CP/environments/staging/diff -H "$A"            # working set vs. live snapshot
curl -s -XPOST $CP/environments/staging/publish -H "$A" -H "$J" -d '{"note":"enforce prompt-injection"}'
```

`publish` validates everything before a version is created: the guardrail version exists and is
not deprecated, every stage is supported, `parallel_group` members are `parallel_safe`, `config`
matches the manifest's JSON schema, and the version is installed on the live gateways. Publishing
identical content returns `"status": "unchanged"`.

**Two-person approval** (production by default):

```bash
curl -s -XPOST $CP/environments/production/publish -H "$A" -H "$J" -d '{"note":"..."}'
# -> {"status":"pending_approval","request":{"id":"...", ...}}
curl -s $CP/publish-requests -H "$B"
curl -s -XPOST $CP/publish-requests/$REQ/approve -H "$B" -H "$J" -d '{"note":"looks good"}'
```

The requester cannot approve their own request. A request becomes `stale` if another version is
published first, so nobody approves a diff they did not see. It `expire`s after
`PUBLISH_REQUEST_TTL_HOURS` (24).

**Rollback** publishes a *new* version with an older version's content and resets the working set
to it, so the next publish does not undo the rollback. Protected environments need approval here too.

```bash
curl -s $CP/environments/production/snapshots -H "$A"
curl -s -XPOST $CP/environments/production/rollback -H "$A" -H "$J" -d '{"version":"production-00011-9b1e04aa"}'
```

**Simulate** runs a request through the working set (`source: "working"`) or the live snapshot
(`"current"`) on a real gateway, without enforcing or auditing it. The control plane sends it to
that environment's gateway from `GATEWAY_URLS` (`{"staging": "http://gw-staging:8100"}`), falling
back to `GATEWAY_URL`. A gateway can simulate any environment: scores and the OPA input use the
target environment, while plugins use that gateway's endpoints. The result says `simulated_on`,
with a warning when they differ. If the gateway can't compile the draft (for example, a guardrail
version it doesn't have), you get 422 with the gateway's reason.

```bash
curl -s -XPOST $CP/simulate -H "$A" -H "$J" -d '{"environment":"staging","source":"working","tenant_id":"acme",
  "stage":"input","request":{"agent_id":"support-bot","action":"llm.chat","payload":{"text":"my SSN is 123-45-6789"}}}'
```

**Fleet and history:**

```bash
curl -s $CP/environments/production/gateways -H "$A"    # heartbeats, versions, `live` flag
curl -s "$CP/changes?entity=snapshot&limit=20" -H "$A"   # append-only change log
curl -s "$CP/analytics/guardrails?environment=production&hours=24" -H "$A"   # needs AUDIT_DSN
# -> summary (requests, by_decision, policy_denied, block_rate), totals per stage/decision with avg and
#    p95 latency, rows per guardrail/version/mode, and an hourly (daily past 72 h) time series.
#    environment and tenant_id are optional filters; tenant keys only see their tenant.
```

## Human review (ESCALATE)

When a guardrail returns ESCALATE, the gateway holds the payload in the control plane's review queue
(encrypted with `REVIEW_ENCRYPTION_KEY`) and answers **202** with an `escalation_id`. The agent
polls `GET /v1/escalations/{id}` on the gateway. The SDK hooks wait up to
`wait_for_review_seconds` (default 0), then raise `GuardrailEscalated`.

```bash
curl -s "$CP/reviews?status=pending" -H "$A"
curl -s "$CP/reviews/$ID?include_raw=true" -H "X-Admin-Key: $RAW_REVIEWER_KEY"
curl -s -XPOST $CP/reviews/$ID/approve -H "$A" -H "$J" -d '{"note":"ok"}'
```

Approved: the gateway releases the held payload. Rejected or not decided within
`REVIEW_TTL_MINUTES` (15): BLOCK. If the review queue cannot be reached, the gateway returns BLOCK
(fail-closed). Reviewers work in the console's **Review queue**. Every detail view and decision is
recorded in the change log; opening the raw payload also records the reviewer on the review.

## Migrating an existing gateway

`import-gateway` copies tenants, gateway API-key hashes (so existing agent keys keep working),
agents, actions and modifiers from the gateway's `guardrail.*` tables. It registers the installed
manifests and imports the snapshot files as each environment's first version.

```bash
python -m app.cli import-gateway --snapshot /snapshots/dev.json --snapshot /snapshots/production.json \
  --plugin-dir /plugins
```

Then switch the gateway to `CONFIG_SOURCE=control_plane`. In Docker Compose, `bootstrap-dev` does
this on the first run only. After that the control plane is the source of truth, and restarts do
not overwrite API edits.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `POSTGRES_DSN` | required | Own schema `control`, own Alembic version table |
| `INTERNAL_TOKEN` | required | Shared with gateways for `/cp/v1/internal/*` |
| `REDIS_URL` | unset | Publish events (polling still works without it) |
| `REVIEW_ENCRYPTION_KEY` | ephemeral (warns) | Fernet key for held payloads. Set it outside dev, or pending reviews become unreadable after a restart |
| `TWO_PERSON_ENVIRONMENTS` | `["production"]` | Environments that need approval |
| `PUBLISH_REQUEST_TTL_HOURS` / `REVIEW_TTL_MINUTES` | 24 / 15 | Expiry |
| `GATEWAY_STALE_SECONDS` | 300 | A gateway without a heartbeat for this long is not `live` |
| `GATEWAY_URL` / `GATEWAY_URLS` | unset | Gateways for `/simulate`: default, and per environment (JSON map) |
| `AUDIT_DSN` | unset | Read-only audit access for `/analytics/guardrails` |
| `CONSOLE_DIR` | `/app/console` | Built console; served at `/console` (and `/review`) when present |
| `PORT` / `INTERNAL_PORT` | 8200 / unset | With `INTERNAL_PORT`, `/cp/v1/internal/*` is only served there |
| `TLS_CERT_FILE`, `TLS_KEY_FILE`, `TLS_CLIENT_CA_FILE`, `TLS_CA_FILE`, `TLS_CLIENT_CERT_FILE`, `TLS_CLIENT_KEY_FILE` | unset | mTLS without a mesh (see [deployment.md](deployment.md#mtls-between-services)) |

Metrics are on `GET /metrics`: pending reviews and the oldest one's age, expired-undecided
reviews, pending publish requests, gateways live, stale and behind per environment, snapshots
published, and review decisions.

`control.change_log`, `control.snapshots` and `control.catalog_versions` are append-only: a
database trigger rejects UPDATE and DELETE.
