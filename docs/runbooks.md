# Runbooks

One section per alert in
[`deploy/helm/guardrail-platform/files/prometheus/guardrail-alerts.yaml`](../deploy/helm/guardrail-platform/files/prometheus/guardrail-alerts.yaml).
The commands assume the Helm release is called `guardrails` in namespace `guardrails`:

```bash
NS=guardrails
P=guardrails-guardrail-platform        # resource name prefix
```

| Alert | Severity | Section |
| --- | --- | --- |
| GuardrailGatewayDown | critical | [gateway-down](#guardrailgatewaydown) |
| GuardrailNoSnapshotLoaded, GatewaysBehindSnapshot | critical / warning | [no-snapshot](#guardrailnosnapshotloaded--gatewaysbehindsnapshot) |
| GuardrailLatencyBudgetExceeded | warning | [latency](#guardraillatencybudgetexceeded) |
| GuardrailErrorRateHigh | warning | [guardrail-errors](#guardrailerrorratehigh) |
| GuardrailBlockRateSpike | warning | [block-rate](#guardrailblockratespike) |
| AuditEventsDropped, AuditSpoolBacklog | critical / warning | [audit](#auditeventsdropped--auditspoolbacklog) |
| GatewayCannotReachControlPlane, ControlPlaneDown, GatewaysStale | warning / critical | [control-plane-unreachable](#gatewaycannotreachcontrolplane--controlplanedown--gatewaysstale) |
| ReviewWaitingTooLong, ReviewsExpiringUndecided | warning | [review-queue](#reviewwaitingtoolong--reviewsexpiringundecided) |
| PublishWaitingForApproval | info | [publishing](#publishwaitingforapproval) |
| GatewayRateLimiting | info | [rate-limits](#gatewayratelimiting) |


The failure model is the same everywhere. A guardrail that can't decide blocks (fail-closed),
so outages show up as blocked agent requests, never as unguarded ones. Recovery is usually
about restoring the dependency. Don't switch assignments to `fail_open` under pressure: that
turns an outage into a data leak.

## GuardrailGatewayDown

**What it means.** No gateway pod exports metrics. Agents calling the gateway get connection
errors. The SDK treats these as blocked, so agents stop, but they are not unguarded.

**Check**

```bash
kubectl -n $NS get pods -l app.kubernetes.io/component=gateway
kubectl -n $NS describe deploy/$P-gateway | tail -20
kubectl -n $NS logs deploy/$P-gateway -c gateway --tail=100
kubectl -n $NS logs deploy/$P-gateway -c migrate            # init container: schema migrations
```

**Common causes**

- *Pods in `Init`*: the `migrate` init container can't reach Postgres (check the Postgres pod or
  external DSN and the NetworkPolicy egress) or is waiting on the migration lock held by another
  pod (that clears on its own).
- *CrashLoopBackOff*: a bad setting. The log says which (`INTERNAL_TOKEN`, TLS files, DSN).
- *ImagePullBackOff*: wrong `global.imageTag` or missing `imagePullSecrets`.
- *Not ready, running*: see [no-snapshot](#guardrailnosnapshotloaded--gatewaysbehindsnapshot). `/ready` also fails without OPA or the database.

**Fix, then verify** `kubectl -n $NS rollout status deploy/$P-gateway` and `helm test guardrails -n $NS`.

## GuardrailNoSnapshotLoaded / GatewaysBehindSnapshot

**What it means.** A gateway has no compiled guardrail snapshot and refuses every request with
503 (fail-closed), or it keeps serving an older snapshot because the new one doesn't compile there.

**Check**

```bash
kubectl -n $NS exec deploy/$P-gateway -c gateway -- python -c \
  "import urllib.request,json;print(json.load(urllib.request.urlopen('http://localhost:8100/ready')))"
```

In the console's **Gateways** page, each gateway shows its snapshot and `last_error`.

**Common causes**

- *A guardrail version in the snapshot isn't installed in this gateway image.* Error:
  `guardrail X@1.2.0 is not installed`. Deploy the image that has it, or roll back the snapshot
  (Pipeline → Published versions → Roll back). Publishing normally refuses this unless `force` was used.
- *A `${VAR}` in the assignment config isn't set on the gateway* (for example
  `AI_GATEWAY_PROJECT_ID`). Add it to the Secret and restart the gateway.
- *Nothing published for this environment yet.* Publish from the console (Pipeline).
- *Control plane unreachable and no disk cache* (new pod during an outage). See
  [control-plane-unreachable](#gatewaycannotreachcontrolplane--controlplanedown--gatewaysstale).

**Verify**: `guardrail_snapshot_loaded` is 1 on every pod, and the console's Gateways page shows healthy.

## GuardrailLatencyBudgetExceeded

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

## GuardrailErrorRateHigh

**What it means.** A guardrail errors or times out on more than 2% of calls. With `fail_closed`
(the default) those requests are blocked; with `fail_open` they pass unchecked. Both need
fixing.

**Check**

```bash
kubectl -n $NS logs deploy/$P-gateway -c gateway --since=15m | grep -i '"level": "ERROR"' | tail -20
```

The `kind` label on `guardrail_errors_total` says *timeout* or *error*.

- **ai-gateway-pii errors**: is the redaction service ready? (`kubectl -n $NS get pods -l app.kubernetes.io/component=redaction`).
  A `401` in the log means `AI_GATEWAY_API_KEY` is wrong or revoked. Recreate it with
  `python -m app.cli ai-gateway-credentials`. A `429` means the key is rate limited: it must be a
  `service` key (unlimited by default).
- **Timeouts**: see [latency](#guardraillatencybudgetexceeded).
- **After a publish**: the new config may be wrong for this guardrail. Simulate it in the console,
  then roll back if needed.

## GuardrailBlockRateSpike

**What it means.** More than 20% of guard requests are blocked. Either something is attacking an
agent, or a change is blocking legitimate traffic.

**Triage in the console**

1. **Analytics**: which stage and which guardrail are blocking? Is it one tenant (filter by tenant)?
   **Decision log** (filter *block*) shows the reason codes and guardrail findings per request.
2. **Activity log**: was anything published or changed just before the spike? (snapshot,
   assignment, agent, action, modifier)
3. **Simulate** a representative request against the live pipeline to see each guardrail's decision.

**If it's a bad change**: roll back (Pipeline → Published versions). In production that needs a
second admin. For a new guardrail, put it back to `shadow` and compare shadow decisions for a
while before enforcing again.

**If it's policy (OPA) denials** (`opa_deny_total`): usually an agent without a profile (trust 0), an
action missing from the catalog (risk 100), or a tool not on the agent's list. Fix the catalog
in Tenants & keys.

**If it's an attack**: keep blocking. Find the API key in the audit log (the `tenant_id` and
`agent_id` columns), then revoke the key or suspend the tenant in the console.

## AuditEventsDropped / AuditSpoolBacklog

**What it means.** Audit events couldn't be written to Postgres.
- **AuditSpoolBacklog** (warning): events are safe on the gateway's disk spool
  (`/var/cache/guardrail-gateway/audit-spool`) and are replayed automatically when Postgres
  accepts writes again.
- **AuditEventsDropped** (critical): the spool was full or unwritable too, so events were lost.
  Decisions still happened, but they are missing from the audit log. Treat this as a compliance
  incident.

**Check**

```bash
kubectl -n $NS logs deploy/$P-gateway -c gateway --since=30m | grep -i audit | tail -20
kubectl -n $NS exec deploy/$P-gateway -c gateway -- du -sh /var/cache/guardrail-gateway/audit-spool
```

**Common causes and fixes**

- *Postgres down or full*: fix Postgres. The spool drains within seconds afterwards
  (`audit_spool_bytes` goes to 0).
- *No partition for the current month* (insert error mentioning the partition): run the
  retention job by hand:
  `kubectl -n $NS create job --from=cronjob/$P-audit-retention audit-partitions-now`.
- *Spool full*: the spool is capped at `AUDIT_SPOOL_MAX_MB` (512) inside a `gateway.audit.spoolSizeLimit`
  emptyDir; raise both together (the chart doesn't set the variable — use `gateway.extraEnv`), then
  fix the database.

**Note** The spool is an `emptyDir`. It survives container restarts but not pod deletion, so
don't delete gateway pods while `audit_spool_bytes > 0` unless you accept losing those events.

## GatewayCannotReachControlPlane / ControlPlaneDown / GatewaysStale

**What it means.** Gateways keep serving with the last snapshot and catalog (cached on disk), so
agents are still guarded. While it lasts:
- publishes, key revocations and score changes don't reach the gateways,
- escalated requests can't be held for review, so they are **blocked** (fail-closed),
- the console is unavailable if the control plane itself is down.

**Check**

```bash
kubectl -n $NS get pods -l app.kubernetes.io/component=control-plane
kubectl -n $NS logs deploy/$P-control-plane -c control-plane --tail=100
kubectl -n $NS exec deploy/$P-gateway -c gateway -- python -c \
  "import urllib.request;print(urllib.request.urlopen('http://$P-control-plane:8200/ready').read())"
```

**Common causes**

- *Control plane pods not ready*: Postgres unreachable (see the migrate init container) or a bad
  `INTERNAL_TOKEN` or `REVIEW_ENCRYPTION_KEY`.
- *Gateway → control plane blocked*: NetworkPolicy. Gateways in another namespace must be
  listed in `networkPolicy.remoteGatewayNamespaces` of the control plane's release, and their own
  (gateway-only) release needs `networkPolicy.controlPlaneNamespace` set.
- *TLS* (`mtls.mode=app`): an expired or mismatched certificate (the log shows a TLS error). Check
  `kubectl get certificate -n $NS` with cert-manager.
- *INTERNAL_TOKEN differs* between the gateway and the control plane: 401 in the gateway log.

**GatewaysStale** alone: a gateway stopped heartbeating (deleted pod, other cluster). Stale
gateways are left out of the "installed on live gateways" check when publishing. If the gateway
is gone for good, nothing else is needed.

## ReviewWaitingTooLong / ReviewsExpiringUndecided

**What it means.** Requests escalated to a person are waiting, or have expired without a
decision. Expired items are **blocked**, so the agent got a refusal.

**Act**

1. Open the console's **Review queue** (it shows pending items first, with a countdown).
2. If a tenant has no reviewers online, create a reviewer key for them
   (Admin keys → New admin key → role `reviewer`, scope the tenant).
3. If one guardrail escalates far too often, look at its decisions in Analytics. It may need a
   tuned threshold, or `shadow` mode, before it floods reviewers.

**Settings**: `controlPlane.reviewTtlMinutes` (default 15). Agents that can wait longer can pass
`wait_for_review_seconds` in the SDK hooks.

## PublishWaitingForApproval

**What it means.** A production publish or rollback has waited more than 4 hours for a second
admin. Nothing is broken, but the change isn't live yet, and the request expires after
`controlPlane.publishRequestTtlHours` (24 h).

**Act.** A different admin opens **Publish approvals** in the console, reviews the field-level diff,
and approves or rejects it. If another version was published in the meantime, the request is
`stale` and has to be requested again: nobody approves a diff they didn't see.

## GatewayRateLimiting

**What it means.** A tenant's API keys are over their per-minute limit, and the gateway answers
429 with `Retry-After`.

**Check.** In the console's Tenants & keys page, each key shows its limit (`default` means
`gateway.rateLimitPerMinute`). The limit applies per key, and the chart divides the global value
across gateway replicas.

**Act.** If the traffic is legitimate, raise that key's limit (Tenants & keys → Limit) or the
global default. If not, revoke the key.
