# GuardrailLatencyBudgetExceeded

**What it means.** p95 guard latency on a stage is above 500 ms, the budget for all guardrails
in one agent turn. Agents are slow; nothing is unguarded.

**Check.** On the Grafana dashboard, look at *p95 latency by guardrail* to find which one is slow.
Then:

- **ai-gateway-pii**: the redaction service (Presidio) is the usual cause. Check its CPU:
  `kubectl -n $NS top pods -l app.kubernetes.io/component=redaction`. Scale it
  (`aiGateway.redaction.replicas` or autoscaling), or raise `analyzerWorkers` if CPU is spare.
  Large retrieval batches cost the most: have agents send fewer or shorter chunks.
- **A remote guardrail**: its own latency. Check its service, then consider a lower
  `timeout_ms` on the assignment (a timeout blocks under fail_closed, so fix the cause first).
- **OPA**: rare. The sidecar runs next to the gateway; check its CPU limit.

**Mitigate.** Scale the gateway and the slow dependency. Guardrails with no data dependency
between them can run in a `parallel_group` if their manifests are `parallel_safe`.
