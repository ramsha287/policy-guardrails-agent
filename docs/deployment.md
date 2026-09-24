# Deploying on k3s (and other Kubernetes)

The Helm chart [`deploy/helm/guardrail-platform`](../deploy/helm/guardrail-platform) runs the
whole platform:
- the gateway with an OPA sidecar,
- the control plane with the console,
- the AI Security Gateway (project-service and the redaction service),
- optionally Postgres and Redis.

It uses only standard Kubernetes APIs (Deployment, StatefulSet, Service, Ingress, HPA, PDB,
NetworkPolicy, CronJob, ConfigMap, Secret). cert-manager and the Prometheus Operator are optional.
[`values-k3s.yaml`](../deploy/helm/guardrail-platform/values-k3s.yaml) and
[`values-cloud.yaml`](../deploy/helm/guardrail-platform/values-cloud.yaml) are the only
differences between clusters.

## 1. Images

The `images` workflow builds multi-arch (amd64 and arm64) images on every push to `main` and
every `v*` tag:

```text
ghcr.io/<owner>/<repo>/guardrail-gateway
ghcr.io/<owner>/<repo>/guardrail-control-plane      (includes the console)
ghcr.io/<owner>/<repo>/ai-gateway-project-service
ghcr.io/<owner>/<repo>/ai-gateway-instant-redaction
```

Tag a release (`git tag v0.5.0 && git push --tags`) so the chart's `appVersion` exists as an
image tag, or set `global.imageTag` (for example `main`). If the packages are private, add an
image pull secret and set `global.imagePullSecrets`.

## 2. Secrets (SOPS)

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

## 3. Install

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
[production.md](production.md#how-access-works).

## Environments

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
  and map each environment to its gateway for simulations (`controlPlane.gatewayUrls`).
- **One cluster per environment.** Each gateway reaches the control plane through its ingress.
  Put the control plane's internal API behind mTLS (below).

## mTLS between services

| `mtls.mode` | What you get | What you need |
| --- | --- | --- |
| `linkerd` (recommended) | mTLS for all pod-to-pod traffic, identity per service account, no app settings | Linkerd installed; the chart adds the injection annotation and NetworkPolicy rules for the proxy port |
| `app` | The gateway and control plane serve their internal routes (`/internal`, `/cp/v1/internal`) on separate ports (8101/8201) that require client certificates; the public ports refuse internal routes | cert-manager (`mtls.app.certManager.enabled`, with an Issuer) or your own Secrets with `ca.crt`, `tls.crt`, `tls.key` |
| `none` | Plain HTTP inside the namespace, restricted by NetworkPolicies | nothing (dev only) |

Docker Compose can do the same without a cluster:
`docker compose -f docker-compose.yml -f docker-compose.mtls.yml up --build`.

## Monitoring

- Metrics: `GET /metrics` on the gateway (8100) and control plane (8200). Pod annotations are
  on by default; with the Prometheus Operator, set `monitoring.serviceMonitor.enabled`.
- Alerts: [`files/prometheus/guardrail-alerts.yaml`](../deploy/helm/guardrail-platform/files/prometheus/guardrail-alerts.yaml)
  (`monitoring.prometheusRule.enabled`, or load the file into a plain Prometheus). Every alert
  links to a [runbook](runbooks/README.md).
- Dashboard: [`files/grafana/guardrail-overview.json`](../deploy/helm/guardrail-platform/files/grafana/guardrail-overview.json).
  Import it, or set `monitoring.grafanaDashboard.enabled` for the Grafana sidecar.
- Traces: set `gateway.otelEndpoint` to an OTLP collector.

## Audit retention

The `audit-retention` CronJob creates the next months' partitions of `audit.audit_events` and
drops those older than `gateway.audit.retentionMonths` (12). Run it on demand with
`kubectl -n guardrails create job --from=cronjob/guardrails-guardrail-platform-audit-retention now`.
Audit events that can't be written while Postgres is down go to a disk spool on the gateway
and are replayed later (see [runbooks/audit.md](runbooks/audit.md)).

## Sizing (3-node k3s, 4 vCPU / 8 GB each)

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

## Upgrades and rollback

`helm upgrade` rolls deployments with `maxUnavailable: 0`. Migrations are additive (new columns
and tables), so the previous version keeps working during a rollout. Roll back the chart with
`helm rollback guardrails`, and a guardrail configuration with the console's rollback: they
are independent.
