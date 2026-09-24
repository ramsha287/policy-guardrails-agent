# GuardrailNoSnapshotLoaded / GatewaysBehindSnapshot

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
  [control-plane-unreachable](control-plane-unreachable.md).

**Verify**: `guardrail_snapshot_loaded` is 1 on every pod, and the console's Gateways page shows healthy.
