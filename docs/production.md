# Running it in production

This page covers how the platform works once it's deployed, and how people get access to it.
The steps for installing on k3s are in [deployment.md](deployment.md).

## The moving parts

```text
                          ┌──────────────────────────── your cluster ─────────────────────────────┐
  AI agent ── gk_ key ──▶ │ Guardrail gateway (:8100) ──▶ OPA policy ──▶ guardrails (ai-gateway …) │
                          │        │ audit log (Postgres)        ▲                                  │
                          │        │ held requests               │ config pushed in seconds         │
                          │        ▼                             │                                  │
  People ── cpk_ key ───▶ │ Control plane (:8200) + console at /console                             │
                          └──────────────────────────────────────────────────────────────────────────┘
```

- **Gateway**: every agent request goes through it. It checks the request, runs the guardrails
  and returns allow, modify, block or escalate. It fails closed: if something breaks, the answer is
  block. Agents authenticate with **gateway keys** (`gk_…`).
- **Control plane and console**: where people manage guardrails, tenants and keys, decide held
  requests, and approve production changes. People authenticate with **admin keys** (`cpk_…`).
- **Postgres** stores configuration and a 12-month append-only audit log. **Redis** pushes config
  changes to the gateways.

The two kinds of keys are separate. An agent's `gk_` key can't open the console, and a person's
`cpk_` key can't call the guard API.

## How access works

There are no usernames or passwords. Each person, or each automated job, gets their own admin key.
The key decides:

| Role | Can do |
| --- | --- |
| `viewer` | Read everything in its scope |
| `reviewer` | Approve or reject held requests (sees a redacted preview) |
| `reviewer-raw` | Reviewer who can also open the raw held payload (every view is logged) |
| `editor` | Change tenants, agents, keys and pipelines; request publishes |
| `admin` | Everything above except raw payloads, plus approving production publishes and managing admin keys |

A key is either **platform-wide** or **limited to one tenant**. A tenant key only sees that
tenant's reviews, agents and keys, and never sees the platform-only screens (publish approvals
and the activity log).

Keys are stored as SHA-256 hashes. The full key is shown once, when it's created. Nobody,
including the platform team, can look it up later. If a key is lost, revoke it and create a new one.

## The first admin key (done once, by whoever installs the platform)

A fresh install has no admin keys, so nobody can sign in. The installer creates the first one from
inside the cluster. That needs `kubectl` access to the namespace, which already means a lot of
trust. Helm prints this command after the install:

```bash
kubectl -n guardrails exec deploy/guardrails-guardrail-platform-control-plane -c control-plane -- \
  python -m app.cli create-admin-key --name alice --roles admin
```

It prints a key like `cpk_3Jf…`. Then:

1. Open `https://<your console host>/console/` and sign in with the key.
2. Create a **second platform admin** for another person (Admin keys → New admin key). Production
   publishes need a second admin to approve them, so one admin can't change production alone.
3. Store the first key in your password manager. After this, people get keys from the console, not
   from `kubectl`.

## How a new person gets a key

1. The new person asks their team lead or a platform admin for access, and says what they need
   to do (for example "review held requests for tenant acme").
2. An admin opens **Admin keys → New admin key** in the console:
   - **Name**: the person, for example `bob`. Use one key per person, so the activity log shows
     who did what.
   - **Roles**: the smallest set that covers the job. Most people only need `reviewer` or `viewer`.
   - **Scope**: their tenant, unless they work on the whole platform.

   Tenant admins (an `admin` key limited to one tenant) can create keys for their own tenant
   without the platform team.
3. The console shows the key once. The admin sends it through a secure channel, such as a
   password-manager share or a one-time secret link. Don't send it over chat or email.
4. The new person opens the console and signs in with the key. The key is kept only in that
   browser tab, and closing the tab signs them out.

When someone leaves or changes teams, an admin clicks **Revoke** on their key. It stops working
straight away, on every control-plane replica.

Scripts and CI jobs get their own keys the same way (for example `ci-publisher` with `editor`),
and read them from a secret store. They send the key in the `X-Admin-Key` header to
`/cp/v1/...`. See [control-plane.md](control-plane.md).

### Lost every admin key?

Run the same `create-admin-key` command as for the first key. Anyone with `kubectl exec` on the
control plane can do this, so keep that access limited to the platform team.

## Connecting an agent in production

1. In the console, go to **Tenants & keys**. Pick or create the tenant, register the agent
   (its trust score and allowed tools) and create a gateway key with **New API key**. You can give
   the key its own rate limit.
2. Put the `gk_` key in the agent's secret store.
3. Point the agent at the gateway, either with the SDK hooks or by using the OpenAI-compatible
   proxy with no code changes ([agent-integration.md](agent-integration.md)).

## What a request goes through

1. The agent sends a stage (input, retrieval, tool, output) to the gateway with its `gk_` key.
   Keys over their rate limit get `429`.
2. The gateway works out who's asking (tenant, agent, trust score) and how risky the action is
   (risk score).
3. OPA checks the policy, for example "production needs trust ≥ 50 and risk ≤ 70", and
   "PII data must go through `ai-gateway-pii`".
4. The guardrails published for this environment run in order. `shadow` guardrails run but
   only get logged.
5. The outcome goes back to the agent:
   - `allow`: carry on.
   - `modify`: use the returned, redacted text.
   - `block`: stop.
   - `escalate`: a person has to decide. The request waits in the **Review queue** for up to
     15 minutes, and if nobody decides it's blocked.
6. Every decision is written to the audit log with scores, reasons and a hash of the payload. The
   raw text is never stored.

## Changing guardrails safely

- Edit the pipeline for **dev** or **staging** in the console, then publish. It goes live on those
  gateways within seconds.
- For **production**, one admin requests the publish and a *different* admin approves it under
  **Publish approvals**. Every publish can be rolled back from the Pipeline page.
- New guardrails usually start in `shadow` mode. Watch Analytics, then switch them to `enforce`.
- Use **Simulate** to try a payload against a draft before publishing. It changes nothing and
  isn't audited.

## Day-to-day operations

- Health and metrics: `/health`, `/ready` and `/metrics` on both services, with Prometheus alerts
  and a Grafana dashboard in the Helm chart.
- On-call runbooks for each alert: [runbooks/](runbooks/README.md).
- Backups: back up Postgres. It holds all configuration and the audit log. Gateways keep a disk
  spool of audit events if Postgres is down, and replay them when it's back.
- Secrets (database passwords, the payload encryption key, the provider key for proxy mode) are
  kept in SOPS-encrypted files ([deploy/secrets](../deploy/secrets/README.md)).

## Optional hardening

- Put the console behind your company's single sign-on at the ingress, for example with
  oauth2-proxy. People then need both a company login and an admin key.
- Only expose `/console` and `/cp/v1` to your office or VPN network. Agents only need to reach
  the gateway.
- Rotate admin keys on a schedule, for example every 90 days: create the new key, hand it
  over, then revoke the old one.
