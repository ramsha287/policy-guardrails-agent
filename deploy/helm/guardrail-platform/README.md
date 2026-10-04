# guardrail-platform Helm chart

It runs the gateway (with an OPA sidecar), the control plane and console, the AI Security Gateway
(project-service and redaction), and, optionally, Postgres and Redis. The full guide is in
[docs/deployment.md](../../../docs/deployment.md).

```bash
helm upgrade --install guardrails deploy/helm/guardrail-platform -n guardrails --create-namespace \
  -f deploy/helm/guardrail-platform/values-k3s.yaml --set secrets.existingSecret=guardrail-secrets
```

## Key values

| Value | Default | Meaning |
| --- | --- | --- |
| `global.environment` | `production` | Environment this release's gateway serves |
| `global.imageRegistry` / `global.imageTag` | GHCR / appVersion | Images built by the `images` workflow |
| `secrets.existingSecret` | `""` | The Secret with every key (see `deploy/secrets`). Required unless `secrets.create` |
| `postgresql.enabled` / `redis.enabled` | `true` | In-chart single instances; `false` = external (DSNs and `REDIS_URL` in the Secret) |
| `gateway.replicas`, `gateway.autoscaling.*` | 2, off | Gateway scale |
| `gateway.rateLimitPerMinute` | `0` | Per API key across all replicas (divided by `replicas`); catalog per-key overrides win |
| `gateway.contextual.riskMode` | `shadow` | `off`, `shadow` (compute and audit only) or `enforce` ([contextual decisions](../../../docs/contextual-decisions.md)) |
| `gateway.contextual.requireBoundKeys` | `false` | Refuse gateway keys not bound to one agent |
| `gateway.contextual.internalDomains` | `""` | Comma-separated internal domains for destination checks |
| `gateway.contextual.riskConfig` | `{}` | Risk weight/limit overrides (`RISK_CONFIG_JSON`) |
| `gateway.verification.oidc*` | `""` | Issuer, audience and JWKS URL for user confirmation ([verification](../../../docs/contextual-decisions.md#verification)) |
| `gateway.verification.sqlDryRun` | `false` | SQL dry run; read-replica DSNs in the Secret key `VERIFY_SQL_DRY_RUN` |
| `gateway.events.sinks` | `""` | Decision events: `redis`, `webhook` or both ([events](../../../docs/contextual-decisions.md#decision-events)) |
| `gateway.events.webhookUrl` | `""` | Webhook sink URL; signed with the Secret key `OUTBOX_WEBHOOK_SECRET` |
| `gateway.proxy.*` | off | OpenAI-compatible `/v1/chat/completions` with the guardrails applied |
| `gateway.configSource` | `control_plane` | Or `file` with `gateway.snapshot` |
| `controlPlane.enabled` | `true` | `false` for gateway-only releases (other environments) |
| `controlPlane.discovery.scheduler` | `true` | Run due discovery connectors ([agent discovery](../../../docs/discovery.md)) |
| `controlPlane.discovery.secretKeys` | `[]` | Secret keys (`DISCOVERY_SECRET_*`) connectors may name as credentials |
| `controlPlane.discovery.kubernetes.enabled` | `false` | Read-only ClusterRole (pods, kagent agents, all namespaces) for the in-cluster Kubernetes connector. Cluster-wide and shared by every tenant's connectors: only platform admins configure connectors, so point one tenant's connector at it or restrict each connector's `namespaces` |
| `controlPlane.discovery.kubernetes.apiServerCIDRs` | `[]` | Required when the Kubernetes connector is enabled: API server addresses for the egress NetworkPolicy (the chart fails without them) |
| `controlPlane.discovery.logs.existingClaim` | `""` | PVC with DNS query logs for the `dns_log` connector (mounted read-only) |
| `controlPlane.twoPersonEnvironments` | `[production]` | Environments that need a second approver |
| `controlPlane.gatewayUrls` | `{}` | Gateway per environment for simulations |
| `controlPlane.ingress.*` | enabled | Console + admin API |
| `aiGateway.redaction.*` | 2 replicas, 1.5 Gi | Presidio sizing |
| `auditRetention.*` | daily | Partition maintenance CronJob (12-month retention) |
| `mtls.mode` | `none` | `linkerd` (recommended) or `app` (cert-manager or your own Secrets) |
| `networkPolicy.*` | enabled | Default-deny plus the platform's flows; `externalEgressCIDRs` for managed databases or the LLM provider |
| `monitoring.*` | annotations | ServiceMonitor, PrometheusRule, Grafana dashboard ConfigMap |

## Files

- `files/policies/*.rego`: the OPA policy for the sidecar, kept identical to `policies/guardrails/`
  (CI checks this). Copy it again after changing the policy:
  `cp policies/guardrails/authz.rego deploy/helm/guardrail-platform/files/policies/`.
- `files/prometheus/guardrail-alerts.yaml`: alert rules, with [runbooks](../../../docs/runbooks/README.md).
- `files/grafana/guardrail-overview.json`: the dashboard.

## Checks

CI runs `helm lint`, renders the defaults, k3s, cloud and mTLS combinations through
`kubeconform -strict`, and runs `promtool check rules` on the alerts.
