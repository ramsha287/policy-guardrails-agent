# Operations: deploy, access, run, upgrade

How to install the platform on Kubernetes or k3s, give people access, run it day to day and
upgrade it. For a laptop, Docker Compose is enough ([README](../README.md#run-it-locally)).

## Production checklist

- `RISK_MODE=shadow` first; read the Decision log for 1–2 weeks; then `enforce`
  ([decisions.md](decisions.md#risk_mode)). Bind every gateway key to its agent, then
  `REQUIRE_BOUND_KEYS=true`.
- Switch `ai-gateway-pii` to **enforce** in production once its shadow results look right (until
  then PII/CONFIDENTIAL requests are blocked by policy there).
- Set `REVIEW_ENCRYPTION_KEY`, `INTERNAL_TOKEN`, `HASH_SECRET` from SOPS-encrypted secrets; give
  `AUDIT_DSN` a read-only user.
- Two platform admins (production publishes need a second one). Reviewers per tenant.
- Run Redis (shared session state across replicas). Keep `/metrics` and `/cp/v1/internal` inside
  the cluster; expose only the gateway to agents and `/console` + `/cp/v1` to your network.
- Leave `controlPlane.playground.environments` empty in production unless you want editors to
  send real traffic from the console.
- Turn on the decision-event outbox and keep the hourly chain heads outside the database if you
  need tamper evidence beyond the append-only trigger.

## Installing on k3s or Kubernetes

The Helm chart [`deploy/helm/guardrail-platform`](../deploy/helm/guardrail-platform) runs the
gateway with an OPA sidecar, the control plane with the console, the AI Gateway (project-service
and the redaction service), and optionally Postgres and Redis. It uses only standard Kubernetes
APIs; cert-manager and the Prometheus Operator are optional.
[`values-k3s.yaml`](../deploy/helm/guardrail-platform/values-k3s.yaml) and
[`values-cloud.yaml`](../deploy/helm/guardrail-platform/values-cloud.yaml) are the only differences
between clusters.

### 1. Images

The `images` workflow builds multi-arch (amd64 and arm64) images on every push to `main` and
every `v*` tag:

```text
ghcr.io/<owner>/<repo>/guardrail-gateway
ghcr.io/<owner>/<repo>/guardrail-control-plane      (includes the console)
ghcr.io/<owner>/<repo>/ai-gateway-project-service
ghcr.io/<owner>/<repo>/ai-gateway-instant-redaction
```

Tag a release (`git tag v0.11.0 && git push --tags`) so the chart's `appVersion` exists as an
image tag, or set `global.imageTag` (for example `main`). If the packages are private, add an
image pull secret and set `global.imagePullSecrets`.

### 2. Secrets (SOPS)

Follow [deploy/secrets/README.md](../deploy/secrets/README.md): fill in
`secrets.example.yaml`, encrypt it with SOPS and age, and apply it:

```bash
kubectl create namespace guardrails
sops --decrypt deploy/secrets/production/guardrail-secrets.enc.yaml | kubectl apply -f -
```

`AI_GATEWAY_PROJECT_ID` and `AI_GATEWAY_API_KEY` come from the redaction service, which must
be running first. Install once with placeholders, run the command below, put the output into
the secret, re-apply it, and restart the gateway:

```bash
kubectl -n guardrails exec deploy/guardrails-guardrail-platform-gateway -c gateway -- \
  python -m app.cli ai-gateway-credentials \
  --project-service-url http://guardrails-guardrail-platform-project-service:8000
kubectl -n guardrails rollout restart deploy/guardrails-guardrail-platform-gateway
```

### 3. Install

```bash
helm upgrade --install guardrails deploy/helm/guardrail-platform -n guardrails \
  -f deploy/helm/guardrail-platform/values-k3s.yaml \
  --set secrets.existingSecret=guardrail-secrets
helm test guardrails -n guardrails
```

Each service runs `alembic upgrade head` in an init container before it starts. Replicas
starting together take turns through a Postgres advisory lock, so there is no separate
migration Job to order.

Then create admin keys (the NOTES printed by Helm show the exact command). Open the console at
`https://<controlPlane.ingress.host>/console/`. Register tenants and gateway keys there, and
publish the first snapshot from the Pipeline page. Gateways register their installed guardrail
versions on their first heartbeat.

How people get access after that (roles, onboarding, revoking, a lost key) is covered in
[access and admin keys](#access-and-admin-keys) below.

### Environments

The control plane manages dev, staging and production. Two common layouts:

- **One cluster, one release per environment.** The production release runs the control plane.
  Staging and dev releases run gateways only:
  ```bash
  helm upgrade --install guardrails-staging deploy/helm/guardrail-platform -n guardrails-staging \
    -f values-k3s.yaml --set global.environment=staging --set controlPlane.enabled=false \
    --set gateway.controlPlaneUrl=http://guardrails-guardrail-platform-control-plane.guardrails:8200 \
    --set networkPolicy.controlPlaneNamespace=guardrails --set secrets.existingSecret=guardrail-secrets
  ```
  In the control plane's release, allow those gateways in (`networkPolicy.remoteGatewayNamespaces`)
  and map each environment to its gateway for simulations (`controlPlane.gatewayUrls`) and, if you
  want the console Playground there, `controlPlane.playground.environments` and `.gatewayUrls`.
- **One cluster per environment.** Each gateway reaches the control plane through its ingress.
  Put the control plane's internal API behind mTLS (below).

### mTLS between services

| `mtls.mode` | What you get | What you need |
| --- | --- | --- |
| `linkerd` (recommended) | mTLS for all pod-to-pod traffic, identity per service account, no app settings | Linkerd installed; the chart adds the injection annotation and NetworkPolicy rules for the proxy port |
| `app` | The gateway and control plane serve their internal routes (`/internal`, `/cp/v1/internal`) on separate ports (8101/8201) that require client certificates; the public ports refuse internal routes | cert-manager (`mtls.app.certManager.enabled`, with an Issuer) or your own Secrets with `ca.crt`, `tls.crt`, `tls.key` |
| `none` | Plain HTTP inside the namespace, restricted by NetworkPolicies | nothing (dev only) |

Docker Compose can do the same without a cluster:
`docker compose -f docker-compose.yml -f docker-compose.mtls.yml up --build`.

### Monitoring

- Metrics: `GET /metrics` on the gateway (8100) and control plane (8200). Pod annotations are
  on by default; with the Prometheus Operator, set `monitoring.serviceMonitor.enabled`.
- Alerts: [`files/prometheus/guardrail-alerts.yaml`](../deploy/helm/guardrail-platform/files/prometheus/guardrail-alerts.yaml)
  (`monitoring.prometheusRule.enabled`, or load the file into a plain Prometheus). Every alert
  links to a [runbook](runbooks.md).
- Dashboard: [`files/grafana/guardrail-overview.json`](../deploy/helm/guardrail-platform/files/grafana/guardrail-overview.json).
  Import it, or set `monitoring.grafanaDashboard.enabled` for the Grafana sidecar.
- Traces: set `gateway.otelEndpoint` to an OTLP collector.
- Gateway metrics include `guardrail_decisions_total{id,mode,…}`, request latency per stage,
  `guardrail_errors_total{kind}`, `opa_deny_total`, `guardrail_snapshot_loaded`, audit spool and
  outbox backlog. Control-plane metrics include pending reviews and the oldest one's age,
  expired-undecided reviews, pending publish requests, gateways live/stale/behind per environment,
  snapshots published, review decisions, and `cp_inventory_*` / `cp_discovery_*`.

### Audit retention

The `audit-retention` CronJob creates the next months' partitions of `audit.audit_events` and
drops those older than `gateway.audit.retentionMonths` (12). Run it on demand with
`kubectl -n guardrails create job --from=cronjob/guardrails-guardrail-platform-audit-retention now`.
Audit events that can't be written while Postgres is down go to a disk spool on the gateway
and are replayed later (see [runbooks.md](runbooks.md#auditeventsdropped--auditspoolbacklog)).

### Sizing (3-node k3s, 4 vCPU / 8 GB each)

| Component | Replicas | Requests |
| --- | --- | --- |
| gateway + OPA | 2 | 250m / 320Mi each |
| control plane | 1–2 | 100m / 192Mi |
| redaction service (Presidio + spaCy large model) | 1–2 | 250–500m / 1.3–1.5Gi |
| project-service | 1 | 50m / 128Mi |
| Postgres (in-chart) | 1 | 100m / 256Mi, 20Gi local-path |
| Redis | 1 | 50m / 64Mi |

The redaction service dominates memory. Scale it (or turn on its HPA) before the gateway when
latency climbs.

### Upgrades and rollback

`helm upgrade` rolls deployments with `maxUnavailable: 0`. Migrations are additive (new columns
and tables), so the previous version keeps working during a rollout. Roll back the chart with
`helm rollback guardrails`, and a guardrail configuration with the console's rollback: they
are independent.

Version notes:

- **Upgrade gateways before binding keys** (0.6+). An older gateway can't read a catalog that
  contains a bound key; the control plane refuses to bind (422) while any gateway heard from in
  the last 15 minutes lacks the `agent_bound_keys` capability. The same guard applies to hosted
  advisors (`advisors_v1`, 0.9+) and the inventory risk fields (`inventory_risk_v1`, 0.10+, left out
  of the catalog until every live gateway has it).
- Migrations are additive: gateway `0002` (nullable columns), `0003` (`guardrail.outbox`); control
  plane `0003`, `0004` (`inventory` schema). The Playground and Decision log need no migration.
- SDK 1.1+ sends `accepts_obligations`, and 1.2+ `verification_channels`, only when you set them;
  send them only to upgraded gateways (older ones reject unknown fields with 422).
- `VERIFICATION_ENABLED=false` sends every `verify` to human review, as before verification existed.

## Access and admin keys

There are no usernames or passwords. Each person, or each automated job, gets their own admin key.
The key decides:

The roles (`viewer`, `reviewer`, `reviewer-raw`, `editor`, `admin`) and what each can do are in
[console.md](console.md#sign-in-and-access).

A key is either **platform-wide** or **limited to one tenant**. A tenant key only sees that
tenant's reviews, agents and keys, and never sees the platform-only screens (publish approvals
and the activity log).

Keys are stored as SHA-256 hashes. The full key is shown once, when it's created. Nobody,
including the platform team, can look it up later. If a key is lost, revoke it and create a new one.

### The first admin key (done once, by whoever installs the platform)

A fresh install has no admin keys, so nobody can sign in. The installer creates the first one from
inside the cluster. That needs `kubectl` access to the namespace, which already means a lot of
trust. Helm prints this command after the install:

```bash
kubectl -n guardrails exec deploy/guardrails-guardrail-platform-control-plane -c control-plane -- \
  python -m app.cli create-admin-key --name alice --roles admin
```

It prints a key like `cpk_3Jf…`. Then:

1. Open `https://<your console host>/console/` and sign in with the key.
2. Create a **second platform admin** for another person (Admin keys → New admin key). Production
   publishes need a second admin to approve them, so one admin can't change production alone.
3. Store the first key in your password manager. After this, people get keys from the console, not
   from `kubectl`.

### How a new person gets a key

1. The new person asks their team lead or a platform admin for access, and says what they need
   to do (for example "review held requests for tenant acme").
2. An admin opens **Admin keys → New admin key** in the console:
   - **Name**: the person, for example `bob`. Use one key per person, so the activity log shows
     who did what.
   - **Roles**: the smallest set that covers the job. Most people only need `reviewer` or `viewer`.
   - **Scope**: their tenant, unless they work on the whole platform.

   Tenant admins (an `admin` key limited to one tenant) can create keys for their own tenant
   without the platform team.
3. The console shows the key once. The admin sends it through a secure channel, such as a
   password-manager share or a one-time secret link. Don't send it over chat or email.
4. The new person opens the console and signs in with the key. The key is kept only in that
   browser tab, and closing the tab signs them out.

When someone leaves or changes teams, an admin clicks **Revoke** on their key. It stops working
straight away, on every control-plane replica.

Scripts and CI jobs get their own keys the same way (for example `ci-publisher` with `editor`),
and read them from a secret store. They send the key in the `X-Admin-Key` header to
`/cp/v1/...`. See [reference.md](reference.md#control-plane-api).

#### Lost every admin key?

Run the same `create-admin-key` command as for the first key. Anyone with `kubectl exec` on the
control plane can do this, so keep that access limited to the platform team.

### Connecting an agent in production

1. In the console, go to **Tenants & keys**. Pick or create the tenant, register the agent
   (its trust score and allowed tools) and create a gateway key with **New API key**, with that
   agent selected. A bound key can only act as its agent; give each agent its own key. You can
   also give the key its own rate limit. Once every key is bound, set
   `gateway.contextual.requireBoundKeys=true` in production
   ([decisions.md](decisions.md#risk_mode)).
2. Put the `gk_` key in the agent's secret store.
3. Point the agent at the gateway, either with the SDK hooks or by using the OpenAI-compatible
   proxy with no code changes ([agent-integration.md](agent-integration.md)).

## Day-to-day operations

- Health and metrics: `/health`, `/ready` and `/metrics` on both services, with Prometheus alerts
  and a Grafana dashboard in the Helm chart.
- On-call runbooks for each alert: [runbooks.md](runbooks.md).
- Backups: back up Postgres. It holds all configuration and the audit log. Gateways keep a disk
  spool of audit events if Postgres is down, and replay them when it's back.
- Secrets (database passwords, the payload encryption key, the provider key for proxy mode) are
  kept in SOPS-encrypted files ([deploy/secrets](../deploy/secrets/README.md)).

## Optional hardening

- Put the console behind your company's single sign-on at the ingress, for example with
  oauth2-proxy. People then need both a company login and an admin key.
- Only expose `/console` and `/cp/v1` to your office or VPN network. Agents only need to reach
  the gateway.
- Rotate admin keys on a schedule, for example every 90 days: create the new key, hand it
  over, then revoke the old one.
