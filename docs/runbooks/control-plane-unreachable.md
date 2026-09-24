# GatewayCannotReachControlPlane / ControlPlaneDown / GatewaysStale

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
  or, with `mtls.mode=app`, an expired or mismatched certificate (the log shows a TLS error).
  Check `kubectl get certificate -n $NS` with cert-manager.
- *INTERNAL_TOKEN differs* between the gateway and the control plane: 401 in the gateway log.

**GatewaysStale** alone: a gateway stopped heartbeating (deleted pod, other cluster). Stale
gateways are left out of the "installed on live gateways" check when publishing. If the gateway
is gone for good, nothing else is needed.
