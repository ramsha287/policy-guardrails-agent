# GuardrailGatewayDown

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
- *Not ready, running*: see [no-snapshot](no-snapshot.md). `/ready` also fails without OPA or the database.

**Fix, then verify** `kubectl -n $NS rollout status deploy/$P-gateway` and `helm test guardrails -n $NS`.
