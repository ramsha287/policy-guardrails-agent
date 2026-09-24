# Runbooks

One page per alert in
[`deploy/helm/guardrail-platform/files/prometheus/guardrail-alerts.yaml`](../../deploy/helm/guardrail-platform/files/prometheus/guardrail-alerts.yaml).
The commands assume the Helm release is called `guardrails` in namespace `guardrails`:

```bash
NS=guardrails
P=guardrails-guardrail-platform        # resource name prefix
```

| Alert | Severity | Runbook |
| --- | --- | --- |
| GuardrailGatewayDown | critical | [gateway-down](gateway-down.md) |
| GuardrailNoSnapshotLoaded, GatewaysBehindSnapshot | critical / warning | [no-snapshot](no-snapshot.md) |
| GuardrailLatencyBudgetExceeded | warning | [latency](latency.md) |
| GuardrailErrorRateHigh | warning | [guardrail-errors](guardrail-errors.md) |
| GuardrailBlockRateSpike | warning | [block-rate](block-rate.md) |
| AuditEventsDropped, AuditSpoolBacklog | critical / warning | [audit](audit.md) |
| GatewayCannotReachControlPlane, ControlPlaneDown, GatewaysStale | warning / critical | [control-plane-unreachable](control-plane-unreachable.md) |
| ReviewWaitingTooLong, ReviewsExpiringUndecided | warning | [review-queue](review-queue.md) |
| PublishWaitingForApproval | info | [publishing](publishing.md) |
| GatewayRateLimiting | info | [rate-limits](rate-limits.md) |

The failure model is the same everywhere. A guardrail that can't decide blocks (fail-closed),
so outages show up as blocked agent requests, never as unguarded ones. Recovery is usually
about restoring the dependency. Don't switch assignments to `fail_open` under pressure: that
turns an outage into a data leak.
