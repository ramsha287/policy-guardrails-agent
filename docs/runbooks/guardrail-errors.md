# GuardrailErrorRateHigh

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
- **Timeouts**: see [latency](latency.md).
- **After a publish**: the new config may be wrong for this guardrail. Simulate it in the console,
  then roll back if needed.
