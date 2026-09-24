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
| `gateway.proxy.*` | off | OpenAI-compatible `/v1/chat/completions` with the guardrails applied |
| `gateway.configSource` | `control_plane` | Or `file` with `gateway.snapshot` |
| `controlPlane.enabled` | `true` | `false` for gateway-only releases (other environments) |
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
