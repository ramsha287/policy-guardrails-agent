# Secrets with SOPS

Every secret the platform needs lives in one Kubernetes Secret per release. The chart only
references it (`secrets.existingSecret`), so secret values never end up in Helm values or the
release history. The Secret is kept in Git encrypted with [SOPS](https://github.com/getsops/sops)
and [age](https://github.com/FiloSottile/age). This works on k3s, needs no extra controller, and
you can add Vault later without changing the chart.

## One-time setup

```bash
age-keygen -o ~/.config/sops/age/keys.txt        # your private key; back it up securely
age-keygen -y ~/.config/sops/age/keys.txt        # your public key (age1...)
```

Put the public keys of everyone (and the CI or deploy system) that may decrypt into
[`.sops.yaml`](.sops.yaml), with separate recipients for production and staging.

## Create or change the secrets

```bash
cd deploy/secrets
mkdir -p production
cp secrets.example.yaml production/guardrail-secrets.enc.yaml
# fill in the values, then:
sops --encrypt --in-place production/guardrail-secrets.enc.yaml
git add production/guardrail-secrets.enc.yaml        # values are encrypted; keys stay readable
sops production/guardrail-secrets.enc.yaml           # later edits: decrypts in your editor, re-encrypts on save
```

## Apply

```bash
sops --decrypt deploy/secrets/production/guardrail-secrets.enc.yaml | kubectl apply -f -
helm upgrade --install guardrails deploy/helm/guardrail-platform -n guardrails \
  -f deploy/helm/guardrail-platform/values-k3s.yaml --set secrets.existingSecret=guardrail-secrets
```

On Windows PowerShell the same commands work (`sops` and `age` have Windows builds). Pipe with
`sops --decrypt ... | kubectl apply -f -`.

GitOps alternatives that decrypt inside the cluster: Flux (`decryption.provider: sops`) or
Argo CD with the KSOPS plugin. With either, only the cluster's age key can decrypt.

After changing a secret, restart the workloads that read it:
`kubectl -n guardrails rollout restart deploy`.

## What goes where

| Key | Used by | Notes |
| --- | --- | --- |
| `INTERNAL_TOKEN` | gateway, control plane | Gateway to control plane calls. Rotate both at once |
| `REVIEW_ENCRYPTION_KEY` | control plane | Rotating it makes pending reviews unreadable, so rotate when the queue is empty |
| `HASH_SECRET` | redaction service | Rotating it changes every `hash` redaction value |
| `AI_GATEWAY_PROJECT_ID`, `AI_GATEWAY_API_KEY` | gateway | Run `python -m app.cli ai-gateway-credentials` once |
| `POSTGRES_PASSWORD` | in-chart Postgres and every service | Only with `postgresql.enabled=true` |
| `*_POSTGRES_DSN`, `AUDIT_DSN` | each service | External Postgres; give `AUDIT_DSN` a read-only user |
| `REDIS_URL` | gateway, control plane, redaction | External Redis |
| `PROXY_UPSTREAM_API_KEY` | gateway | Proxy mode only |

## Don't

- commit a decrypted file (`.gitignore` blocks `*.dec.yaml` and `**/secrets.yaml`)
- use `secrets.create=true` outside a trial: it stores the values in the Helm release
- share one age key between production and staging
