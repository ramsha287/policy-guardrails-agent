# Guardrail Platform for AI Agents

**A safety checkpoint between your AI agents and the world.** Before an agent sends a prompt,
uses retrieved documents, calls a tool or returns an answer, it asks the guardrail gateway
whether that's OK. The gateway checks the request against your policies, runs the guardrails you
chose for that step, and answers **allow**, **modify**, **block** or **escalate** (send it to a
person to decide). Every decision is logged.

It's built from scratch, runs on k3s or any Kubernetes cluster, and any kind of
guardrail (PII, prompt injection, toxicity, secrets, …) plugs in without changing the core.

```text
  AI agent ──▶ Gateway ──▶ who is asking? how risky? ──▶ Policy (OPA) ──▶ Guardrails ──▶ decision
                  │                                                         │
                  └── audit log (12 months, no raw text)          held requests ──▶ human review
```

## Guardrails

> **Available now: the AI Gateway.** The platform ships with `ai-gateway-pii`, which connects
> every agent to the existing **AI Gateway** (`services/ai-gateway`, Presidio). It finds personal
> data in prompts, retrieved documents, tool calls and answers, redacts it, and blocks the
> riskiest cases, such as SSNs, card numbers, or PII sent to external tools.

| Guardrail | What it checks | Status |
| --- | --- | --- |
| **`ai-gateway-pii`**, via the **AI Gateway** | Personal data: emails, names, phone numbers, SSNs, card numbers, national IDs, your own patterns | **Available now.** On by default on input, retrieval, tool and output |
| Policy checks (OPA) | Trust and risk scores, allowed tools, delegation depth, required guardrails | **Available now.** Always on |
| Prompt injection, toxicity, secrets, topic limits, grounding, … | Other kinds of content | **Not built yet.** Add them as plugins ([how](docs/adding-a-guardrail.md)) |

The full catalog, with what the AI Gateway detects, its settings and how every guardrail
behaves, is in **[docs/guardrails.md](docs/guardrails.md)**.

## What you get

- **PII protection out of the box, through the AI Gateway.** Emails, names, IDs and the like are
  redacted, and SSNs and card numbers are blocked. The privacy team manages the entity list and
  custom patterns in one place, the AI Gateway project.
- **Room for every other guardrail.** Local rules, remote services and ML models all use the same
  plugin interface, conformance tests and shadow-then-enforce rollout.
- **Four checkpoints per agent run:** input, retrieval, tool calls and output.
- **Scores for agents and actions.** Each agent has a trust score and each action has a risk
  score, and policies use both (for example "no risky actions in production for low-trust
  agents").
- **Human review.** Uncertain cases wait in a review queue in the web console, where a person
  approves or rejects them.
- **Safe changes.** Try changes in dev, run new guardrails in shadow mode, and publish to
  production only after a second admin approves. Every publish can be rolled back.
- **Separate tenants**, each with its own agents, keys, reviews and rate limits.
- **Fails closed.** If anything breaks, the answer is block, in every environment.

## Try it in 5 minutes

You need Docker.

```bash
git clone https://github.com/ramsha287/policy-guardrails-agent && cd policy-guardrails-agent
docker compose up --build
```

When it's up, get the keys the first run generated:

```bash
docker compose exec guardrail-control-plane cat /bootstrap/cp.env   # CP_ADMIN_KEY (for you), CP_APPROVER_KEY (a second admin)
docker compose exec guardrail-gateway cat /bootstrap/dev.env        # DEMO_GATEWAY_API_KEY (for an agent)
```

**Open the console:** http://localhost:8200/console/ and sign in with `CP_ADMIN_KEY`.

**Act like an agent**, with the gateway key:

```bash
curl -s localhost:8100/v1/guard/input -H "X-API-Key: gk_..." -H 'content-type: application/json' -d '{
  "agent_id": "research-agent", "action": "llm.chat", "user_id": "u1",
  "data_classification": "PII",
  "payload": {"text": "Email jane.doe@example.com about invoice EMP-123456"}
}'
```

You get `"decision": "modify"` with the email and employee ID redacted by the AI Gateway. Try a
US SSN and you get `block`. Then open **Analytics** or **Overview** in the console to see the requests you just made.

## How to use it

| I want to… | Read |
| --- | --- |
| See every guardrail, what the AI Gateway detects, and how to configure it | [Guardrails](docs/guardrails.md) |
| Use the console: review held requests, change guardrails, simulate | [User guide](docs/user-guide.md) |
| Put it in production, and give people access (admin keys) | [Production guide](docs/production.md) |
| Install on k3s / Kubernetes with Helm | [Deployment](docs/deployment.md) |
| Connect my agent (SDK, LangGraph, CrewAI, or OpenAI-compatible proxy) | [Agent integration](docs/agent-integration.md) |
| Write a new guardrail | [Adding a guardrail](docs/adding-a-guardrail.md) |
| Automate through the API | [Control plane API](docs/control-plane.md) |
| Look up status codes, scoring rules, audit, tests, repo layout | [Reference](docs/reference.md) |
| Handle an alert | [Runbooks](docs/runbooks/README.md) |

### Who gets which key?

There are two kinds of keys:

- **Admin keys (`cpk_…`)** are for people and scripts that use the console or the control-plane
  API. Each key has roles (`viewer`, `reviewer`, `reviewer-raw`, `editor`, `admin`) and can be
  limited to one tenant.
- **Gateway keys (`gk_…`)** are for AI agents calling the gateway. You create them in the
  console under **Tenants & keys**.

In production, the person who installs the platform creates the first admin key with one
command. After that, admins give everyone else their own keys from the console's **Admin keys**
page. The [production guide](docs/production.md#how-access-works) walks through it.

## Connect an agent in a few lines

With no code changes, point any OpenAI client at the gateway (proxy mode):

```python
client = OpenAI(base_url="http://localhost:8100/v1", api_key="gk_...")
```

Or check each step yourself with the SDK:

```python
from guardrail_sdk import GuardClient, GuardHooks, GuardrailBlocked

async with GuardClient("http://localhost:8100", "gk_...", agent_id="research-agent") as client:
    hooks = GuardHooks(client, user_id=user_id, data_classification="PII")
    try:
        prompt = await hooks.before_llm(user_text)                 # input
        chunks = await hooks.on_retrieval(search(prompt))          # retrieval
        answer = await hooks.after_llm(await llm(prompt, chunks))  # output
    except GuardrailBlocked as exc:
        answer = f"Request blocked: {exc.reason}"
```

Proxy mode is off by default (`PROXY_ENABLED=true` turns it on).

## What's inside

| Part | Port | What it does |
| --- | --- | --- |
| `services/guardrail-gateway` | 8100 | Checks every agent request, runs the guardrails and writes the audit log |
| `services/guardrail-control-plane` | 8200 | Stores config, tenants, keys and the review queue; serves the console at `/console` |
| `apps/console` | — | The web console (React) |
| `services/ai-gateway` | 8000/8001 | **The AI Gateway**: the existing PII redaction service behind `ai-gateway-pii` |
| `packages/guardrail-sdk` | — | Python SDK for agents and for writing guardrails |
| `deploy/helm/guardrail-platform` | — | Helm chart for k3s/Kubernetes |
| `policies/guardrails` | — | OPA (Rego) policies |

Full layout: [docs/reference.md](docs/reference.md#repository-layout).

## Run the tests

```bash
pip install -e "packages/guardrail-sdk[test]" -r services/guardrail-gateway/requirements-dev.txt
pytest packages/guardrail-sdk tests/e2e
opa test policies
cd apps/console && npm install && npm test && npm run build && npm run e2e
```

Every suite, including the Postgres ones, is listed in [docs/reference.md](docs/reference.md#tests).

## Project status

All five phases of the build plan are done: foundations, gateway and engine, the AI Gateway PII
guardrail, retrieval and tool stages, the control plane with human review, and hardening for
production (console, Helm chart, mTLS, SOPS secrets, rate limits, durable audit, alerts and
dashboards, proxy mode, multi-arch images).

**Guardrails today:** `ai-gateway-pii` (the AI Gateway) and the OPA policy checks. The next
guardrails, such as prompt injection, toxicity and secrets, are not built yet. See
[docs/guardrails.md](docs/guardrails.md#guardrails-you-can-add).
