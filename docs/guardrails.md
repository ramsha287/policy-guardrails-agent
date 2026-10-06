# Guardrails

A guardrail is one check the gateway runs on an agent's request, such as "does this text contain
personal data?" or "is this a prompt-injection attempt?". The platform itself doesn't depend on
any particular check. Guardrails are plugins, and you choose which ones run in each environment,
at each stage, and for which tenants and agents.

This page lists every guardrail, explains the rules they all follow, documents each one's
settings, and shows how to add a new one. Guardrails run after the policy check (OPA) and before
the decision table; see [architecture.md](architecture.md#one-request-step-by-step).

## At a glance

| Guardrail | What it checks | Stages | Status |
| --- | --- | --- | --- |
| **[`ai-gateway-pii`](#ai-gateway-pii-the-ai-gateway)** | Personal data (emails, names, phone numbers, SSNs, card numbers, national IDs, your own patterns), using the **AI Gateway** (Presidio) | input, retrieval, tool, output | **Available now.** On by default |
| [Policy checks (OPA)](decisions.md#policy-opa) | Whether the agent may do this at all: trust and risk scores, allowed tools, delegation depth, required guardrails | every stage | **Available now.** Always on, part of the gateway |
| **[`secrets`](#secrets-credentials-in-any-stage)** | API keys, tokens, private keys and passwords, by their published formats | input, retrieval, tool, output | **Available.** Shadow in dev; enforce when ready |
| **[`prompt-injection`](#prompt-injection-instructions-hidden-in-content)** | Instructions hidden in user input, retrieved documents and tool results (heuristic) | input, retrieval, tool | **Available.** Shadow in dev; measure before enforcing |
| **[`topic-limits`](#topic-limits-what-the-agent-is-for)** | Denied topics, and requests outside what the agent is for | input, output | **Available.** Needs your topic lists |
| **[`content-moderation`](#content-moderation-harmful-content)** | Harassment, hate, violence, self-harm, sexual content, via an OpenAI-compatible moderation endpoint | input, output | **Available.** Needs an endpoint and key |
| [`noop`](#noop-the-template) | Nothing (always allows) | every stage | Available. A template and engine smoke test, not a real control |
| [Grounding, tool argument rules, step limits, …](#guardrails-not-built-yet) | Other checks | your choice | **Planned.** The platform is ready for them |

> **Today, the AI Gateway is the platform's content guardrail.** Every request marked `PII` or
> `CONFIDENTIAL` must pass through `ai-gateway-pii` on input, retrieval, tool and output, or it's
> blocked. Other guardrails plug in beside it without changing the gateway, the engine or the
> policies.

## How every guardrail works

These rules apply to any guardrail, current or future.

**Stages.** An agent run has checkpoints, and a guardrail declares which ones it supports:

| Stage | What is checked |
| --- | --- |
| `input` | The prompt or messages going to the model |
| `retrieval` | Documents or chunks fetched for the model (RAG) |
| `tool` | A tool call's arguments before it runs, and its result afterwards |
| `output` | The model's answer before the user sees it |
| `agent` | Agent-level events, such as a delegation to another agent |

**Decisions.** Each guardrail answers one of:

- **allow**: carry on unchanged.
- **modify**: carry on with a changed payload, such as redacted text.
- **block**: stop the request.
- **escalate**: hold the request for a person in the console's review queue.

When several guardrails run on one stage, the strictest answer wins: **block > escalate > modify >
allow**. A modified payload goes on to the next guardrail.

**Modes.** An assignment runs in `enforce` mode, where it changes the outcome, or in `shadow` mode,
where it runs and is logged but has no effect. Start every new guardrail in shadow mode, watch it
in **Analytics**, then switch it to enforce.

**Failures.** If a guardrail errors or times out, its `failure_mode` decides the outcome. Real
guardrails use `fail_closed`, so the request is blocked, in every environment.

**Scopes.** An assignment applies to everyone (`global`), to one tenant (`tenant`, for example
`acme`) or to one agent (`agent`, for example `acme/support-bot`). For each guardrail, the most
specific scope wins.

**Kinds.** A guardrail runs in the gateway's process (`local`), as a separate HTTP service
(`remote`), or as an ML model on its own nodes (`model`).

**Privacy.** Guardrails never put raw sensitive values in their reasons, findings or logs. The
audit log keeps decisions, entity types, offsets and a hash of the payload, never the text itself.

**Precedence and order.** Assignments run in `order`; consecutive ones that share a
`parallel_group` run concurrently (only `parallel_safe` guardrails, which never MODIFY). MODIFY
passes the changed payload on; BLOCK and ESCALATE stop the stage after the current group.

**Escalate needs the control plane.** ESCALATE holds the payload in the control plane's review
queue and returns 202. With `CONFIG_SOURCE=file` there is no queue, so ESCALATE becomes BLOCK.

Where to change guardrails: **Pipeline** in the [console](console.md#change-which-guardrails-run), or the
[control plane API](reference.md#control-plane-api). Try a change on the draft with **Simulate**,
and on the live pipeline with the **Playground**.

---

## `ai-gateway-pii`: the AI Gateway

**Status: available now, and the default content guardrail in every environment.**

`ai-gateway-pii` connects the platform to the **AI Gateway** (the existing AI Security Gateway in
`services/ai-gateway`). The AI Gateway uses [Presidio](https://microsoft.github.io/presidio/) to
find personal data and redact it. The guardrail is a thin adapter: detection, the entity list,
custom patterns and the redaction style all live in the AI Gateway, so the privacy team manages
them in one place for every product that uses it.

```text
  gateway ──▶ ai-gateway-pii ──▶ AI Gateway instant-redaction-service (:8001, Presidio)
                                        │
                                        └── project config from project-service (:8000):
                                            entities, custom regex, replace / mask / hash
```

### What it does at each stage

| Stage | What it sends to the AI Gateway | What happens with the default config |
| --- | --- | --- |
| `input` | The user's messages (`scan_roles: [user]`) | PII is redacted (**modify**). A US SSN is **blocked** |
| `retrieval` | All retrieved chunks in one batch (up to 100 per call) | PII in chunks is redacted. Chunks containing an SSN or card number, or more than 20 findings, are dropped |
| `tool` | Tool arguments and results as JSON (every string value is checked) | PII is redacted. **PII sent to a tool that leaves your network** (`http.*`, `email.*`, `slack.*`, `webhook.*`) is **blocked** |
| `output` | The assistant's answer (`scan_roles: [assistant]`) | PII is redacted. Card numbers and SSNs are **blocked** |

Every finding reports the entity type, where it was found (offsets or a JSON path such as
`$.rows[0].email`) and a confidence score. It never includes the matched value.

### What it detects

The AI Gateway project decides which entities are checked. The demo project seeded by
`docker compose` checks:

`EMAIL_ADDRESS`, `PHONE_NUMBER`, `PERSON`, `CREDIT_CARD`, `US_SSN`, `IN_AADHAAR`, `IN_PAN`, and a
custom pattern `EMP-\d{6}` redacted as `[EMPLOYEE_ID]`.

A project can turn on any of the entities the AI Gateway supports:

| Area | Entities |
| --- | --- |
| Contact and identity | `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `LOCATION`, `URL`, `IP_ADDRESS`, `DATE_TIME`, `NRP` |
| Financial | `CREDIT_CARD`, `IBAN_CODE`, `US_BANK_NUMBER`, `CRYPTO` |
| United States | `US_SSN`, `US_ITIN`, `US_PASSPORT`, `US_DRIVER_LICENSE`, `MEDICAL_LICENSE` |
| United Kingdom | `UK_NHS`, `UK_NINO` |
| India | `IN_AADHAAR`, `IN_PAN`, `IN_PASSPORT`, `IN_VOTER`, `IN_VEHICLE_REGISTRATION` |
| Australia | `AU_ABN`, `AU_ACN`, `AU_TFN`, `AU_MEDICARE` |
| Singapore | `SG_NRIC_FIN` |
| Your own | Any regex, with the label to redact it as (for example `[EMPLOYEE_ID]`) |

The redaction style is also set per project: `replace` (`[EMAIL_ADDRESS]`), `mask` (the value
becomes `*` characters) or `hash` (HMAC-SHA256 with a per-project secret, so the same value always
gets the same token).

### Where it runs by default

The snapshot files in `services/guardrail-gateway/config/snapshots/` seed each environment
(Docker Compose imports `dev.json`; `import-gateway` imports any of them; a fresh Helm install
starts with nothing published):

| Environment | Mode | Effect |
| --- | --- | --- |
| dev | enforce | Redacts and blocks as described above (with `secrets` and `prompt-injection` in shadow) |
| staging | enforce | Same as dev |
| production | **shadow** | Runs and is logged, but has no effect. Because the OPA policy requires an **enforced** `ai-gateway-pii` for `PII` and `CONFIDENTIAL` data, those requests are **blocked** in production until you switch it to enforce |

Switch production to enforce once the shadow results look right. In **Pipeline**, pick
production, set `global-ai-gateway-pii` to **enforce** and click **Request publish**. A second
admin approves it under **Publish approvals**.

### Configuration

Set in the assignment's `config` (the console's Pipeline screen, or the API):

| Setting | Meaning | Default |
| --- | --- | --- |
| `project_id` | The AI Gateway project to use (required) | — |
| `base_url` | Where the AI Gateway's instant-redaction-service is | `http://instant-redaction-service:8001` |
| `input.on_detect`, `output.on_detect` | What to do when PII is found: `modify`, `block` or `allow` | `modify` |
| `input.block_entities`, `output.block_entities` | Entity types that always block | none |
| `input.scan_roles`, `output.scan_roles` | Which message roles to check | `user` on input, `assistant` on output |
| `retrieval.on_detect` | As above, for retrieved chunks | `modify` |
| `retrieval.block_entities` | Chunks containing these are dropped | none |
| `retrieval.drop_chunk_if_entities_gt` | Drop a chunk with more findings than this | no limit |
| `tool.arguments`, `tool.result` | `on_detect` and `block_entities` for each side of a tool call | `modify` |
| `tool.external_tools` | Tool name patterns that leave your network | none (the dev/staging snapshots set `http.*`, `email.*`, `slack.*`, `webhook.*`) |
| `tool.external_on_detect` | What to do with PII going to those tools: `block` or `modify` | `block` |

The full example is `global-ai-gateway-pii` in
`services/guardrail-gateway/config/snapshots/dev.json`.

### Versions

| Version | Stages | Notes |
| --- | --- | --- |
| 1.1.0 | input, retrieval, tool, output | Current. Latency budget 800 ms for a batch of 20 chunks, about 300 ms for text |
| 1.0.0 | input, output | Kept so you can roll back |

Both use `fail_closed`: if the AI Gateway is down or slow (time-out 1.5 s), the request is blocked.

### Quality

`eval/datasets/pii_v1.jsonl` has 880 labelled cases (220 per stage, half with PII and half with
look-alikes such as order numbers). The e2e CI job measures precision and recall against the real
AI Gateway. See [eval/README.md](../eval/README.md).

### Code and related docs

- Adapter: `services/guardrail-gateway/app/plugins/ai_gateway_pii/`
- AI Gateway: `services/ai-gateway/` (project-service and instant-redaction-service)
- What changed in the AI Gateway for this platform: [services/ai-gateway/README.md](../services/ai-gateway/README.md)
- If it's failing: [runbooks.md](runbooks.md#guardrailerrorratehigh)

---

## `secrets`: credentials in any stage

**Status: available.** In process, deterministic, no network.

Finds credentials by their published formats: AWS access and secret keys, GitHub, Slack, OpenAI,
Anthropic, Stripe and Google keys, JWTs, PEM private keys, database URLs with a password, and this
platform's own `gk_`/`cpk_` keys. It also finds `password=...`/`api_key: ...`-style assignments
whose value looks random (Shannon entropy at least `min_entropy`), and skips placeholders such as
`${API_KEY}`, `<your-token>`, `********` or `changeme`.

| Setting | Meaning | Default |
| --- | --- | --- |
| `on_detect` | `modify` redacts each secret as `<SECRET:TYPE>`; `block` blocks the request | `modify` |
| `block_types` | Types that always block, whatever `on_detect` says | `[PRIVATE_KEY]` |
| `ignore_types` | Detectors to switch off (for example `JWT` where tokens are passed on purpose) | none |
| `min_entropy` | Bits per character for assignment values | `3.0` |
| `scan_tool_arguments`, `scan_tool_result` | Which side of a tool call to check | both |

Findings carry the type, offsets and location, never the value. A payload too large to scan in
full is blocked (it's `fail_closed`: a secret past the cut can't be vouched for). It runs in
**shadow** in dev by default. Quality: `python eval/generate_secrets_dataset.py` builds a labelled set (220 cases per
stage, half with look-alikes such as UUIDs, git SHAs, checksums and placeholders); the set isn't
committed because it is full of credential-shaped strings. On that synthetic set precision and
recall are 1.0, which says the formats are covered, not how it does on your traffic.

## `prompt-injection`: instructions hidden in content

**Status: available.** In process, heuristic, no network.

Scores text for the common shapes of injected instructions: attempts to override earlier
instructions, fake system turns and chat-template tokens, persona switches, directives to send
data to an address, markdown image beacons, requests to hide something from the user, and hidden
Unicode (tag characters, zero-width and bidi runs). Each text gets a score from the categories it
matches; the request's score is its highest. It checks user input, retrieved chunks and tool
**results** (not the agent's own tool arguments).

| Score | Retrieval | Input, tool results |
| --- | --- | --- |
| below `escalate_at` (0.5) | allow (weak signals go in metadata) | allow |
| `escalate_at` to `block_at` | the chunk is **dropped** (MODIFY), or `escalate`/`block` per `retrieval_action` | **escalate** |
| at or above `block_at` (0.85) | **block** | **block** |

Add your own patterns with `extra_patterns` (`name`, `pattern`, `weight`). A heuristic catches common,
unsophisticated injections and misses paraphrases, so don't rely on it alone: the contextual
decisions (taint labels after untrusted content, `SENSITIVE_THEN_EXTERNAL`) don't depend on
spotting the injection at all. It runs in **shadow** in dev by default. Measure it on your own
traffic in shadow mode, or on a public benchmark your security team chooses, before enforcing;
the repository ships unit and conformance tests for it but no labelled injection set.

## `topic-limits`: what the agent is for

**Status: available.** In process, deterministic. Needs configuration.

Two optional lists per assignment (so per tenant or per agent). A topic is a name plus keywords
(whole words or phrases) and/or regular expressions.

```json
{"denied_topics": [{"name": "legal-advice", "keywords": ["lawsuit", "sue", "legal advice"]}],
 "allowed_topics": [{"name": "billing", "keywords": ["invoice", "refund", "payment"]}],
 "on_denied": "block", "on_out_of_scope": "escalate", "min_words_for_scope": 4}
```

A message that matches a denied topic is blocked (or escalated). When `allowed_topics` is set, a
message of at least `min_words_for_scope` words that matches none of them is out of scope
(escalated by default). Findings name the topic, never the text.

Patterns come from config, and Python's regular expressions have no time limit, so they follow
simple rules (also for `prompt-injection`'s `extra_patterns`): no unbounded repetition of a group
(`(ab)+` is refused; repeat a character or class instead, `[a-z]+`), no backreferences, named
groups or inline flags, at most 300 characters; and they only look at the first 16,384 characters
of each text. Keywords have no such limits.

## `content-moderation`: harmful content

**Status: available.** Remote. Needs an endpoint and key (Helm `gateway.moderation`; Compose `MODERATION_API_KEY`).

Sends the user's and assistant's messages to an OpenAI-compatible `/moderations` endpoint:
OpenAI's moderation API, or a self-hosted model behind the same API when the text must stay in
your network. Categories in `block_categories` block (default `sexual/minors`); other flagged
categories escalate (`on_flagged`). `thresholds` let you flag on scores instead of the endpoint's
own booleans.

The endpoint and key are set by the operator, never by assignment config, so an editor can't
point the key at another host: `MODERATION_BASE_URL` (default `https://api.openai.com/v1`) and
`MODERATION_API_KEY` (Helm: `gateway.moderation`). Long texts are split into 32,000-character
pieces and every piece is moderated. It is `fail_closed` by default (an unreachable endpoint, or a
payload too large to moderate in full, blocks); override per assignment if an outage of the
moderation service shouldn't stop traffic.

## `noop`: the template

**Status: available, but it isn't a safety control.**

`noop` always allows. It runs in shadow mode in every environment to prove the engine runs local
guardrails, and it is the starting point for writing your own (`services/guardrail-gateway/app/plugins/noop/`).

## Guardrails not built yet

Each would be a new plugin with its own manifest, rolled out in shadow mode first, without changes
to the gateway, engine or policies.

| Guardrail | What it would check | Likely stages | Kind |
| --- | --- | --- | --- |
| Model-based prompt injection | A classifier model alongside the heuristic | input, retrieval, tool | `model` |
| Grounding | Answers not supported by the retrieved sources | output | `model` |
| Tool argument rules | Allowed domains, amount limits, read-only checks on tool calls | tool | `local` |
| Agent step and cost limits | Runaway loops, too many steps or tokens per run | agent | `local` |

## Adding a guardrail

A new guardrail is a plugin plus a snapshot entry. You don't change the engine, the gateway
or OPA. Every plugin in `services/guardrail-gateway/app/plugins/` is a working example: `noop`
and `secrets` (local), `ai-gateway-pii` and `content-moderation` (remote adapters).

### 1. Pick a kind

| Kind | Use it for | How it runs |
| --- | --- | --- |
| `local` | Fast rule checks (regex, allow and deny lists, step limits) | A Python class in the gateway process |
| `remote` | Anything in another language or with heavy dependencies | An HTTP service implementing `POST /evaluate` and `GET /health` (generic protocol), or a custom adapter class through `entrypoint` |
| `model` | ML classifiers (prompt injection, toxicity) | Same as `remote`, deployed on its own nodes (for example GPU) |

### 2. Write the manifest (`guardrail.yaml`)

```yaml
id: my-classifier                # kebab-case, unique
version: 1.0.0                   # semver; any change is a new version
kind: local
description: Scores text with a classifier and blocks above a threshold.
owner: ai-security
data_handling: Reads input text only; stores nothing.
stages: [input, retrieval]
decisions_emitted: [allow, block]
failure_mode: fail_closed
latency_budget_ms: 50
capabilities:
  parallel_safe: true            # never emits MODIFY, so it can share a parallel_group
entrypoint: app.plugins.my_classifier.guardrail:MyClassifier
config_schema: {type: object}
```

The manifest is validated when it's loaded. Unknown keys, bad ids, MODIFY without
`emits_modify`, `parallel_safe` combined with MODIFY, and an incompatible `sdk_version` are
all rejected.

### 3. Implement it

```python
from pydantic import BaseModel, ConfigDict
from guardrail_sdk import Decision, Finding, Guardrail, GuardrailResult, Payload, SecurityContext


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")   # reject unknown keys (requirement B6)
    threshold: float = 0.8


class MyClassifier(Guardrail):
    config_model = Config

    async def evaluate(self, context: SecurityContext, payload: Payload) -> GuardrailResult:
        score = await self._score(payload)          # never block the event loop
        if score >= self.config.threshold:
            return GuardrailResult(decision=Decision.BLOCK, reason="prompt injection suspected",
                                   risk_score=int(score * 100),
                                   findings=[Finding(type="PROMPT_INJECTION", score=score, location="text")])
        return GuardrailResult(decision=Decision.ALLOW, reason="clean", risk_score=int(score * 100))
```

Rules that the conformance suite enforces:

- Return only decisions listed in `decisions_emitted`. MODIFY must return a payload with the same shape.
- Never mutate `context`. Be deterministic for the same input, config and version.
- Never put raw sensitive values in `reason`, `findings` or `metadata`.
- Use `self.ctx.http` for HTTP calls, `self.ctx.secrets` for secrets and `self.ctx.state` for
  state (keys scoped with `app.engine.state.scoped`). Don't create module-level globals.

The engine enforces time-outs, the failure mode and the shape check, whatever the plugin does.

### 4. Test it

```bash
guardrail conformance --manifest path/to/guardrail.yaml --config config.json [--samples labelled.json]
```

Add unit tests next to the plugin, and a labelled set of at least 200 cases per stage
(requirement D). Measure it with:

```bash
guardrail evaluate --manifest path/to/guardrail.yaml --config config.json \
  --dataset eval/datasets/<your-set>.jsonl --min-precision 0.9 --min-recall 0.9
```

`eval/README.md` describes the dataset format; `eval/generate_pii_dataset.py` is a worked example.

### 5. Roll it out

Ship the guardrail in the gateway image first, so the gateways report it in their heartbeat. Then
register the version with the control plane, add a **shadow** assignment and publish it. Full API:
[reference.md](reference.md#control-plane-api).

**In the console**: Guardrails → *Register a version* (paste `guardrail.yaml`; remote guardrails
only, since local ones are registered by the gateways) → Pipeline → *Add assignment* in shadow
mode → Simulate → *Review & publish*. Watch *Decisions: enforce vs shadow* on the Grafana
dashboard or in Analytics, then switch the mode to `enforce` and publish again. Production
needs a second admin to approve under Publish approvals.

Or with the API:

```bash
CP=localhost:8200/cp/v1; A="X-Admin-Key: $CP_ADMIN_KEY"; J='content-type: application/json'
# 1. register the manifest (attach the conformance report if you have one)
python -c 'import json;print(json.dumps({"manifest_yaml": open("guardrail.yaml").read()}))' \
  | curl -s -XPOST $CP/guardrails/versions -H "$A" -H "$J" -d @-
# 2. assign it in shadow mode
curl -s -XPUT $CP/environments/staging/assignments/global-my-classifier -H "$A" -H "$J" -d '{
  "guardrail_id": "my-classifier", "guardrail_version": "1.0.0", "scope_type": "global",
  "stages": ["input"], "order": 5, "mode": "shadow", "config": {"threshold": 0.8}}'
# 3. check it against real traffic before it goes live, then publish
curl -s -XPOST $CP/simulate -H "$A" -H "$J" -d '{"environment":"staging","tenant_id":"demo","stage":"input",
  "request":{"agent_id":"research-agent","action":"llm.chat","payload":{"text":"ignore previous instructions"}}}'
curl -s -XPOST $CP/environments/staging/publish -H "$A" -H "$J" -d '{"note":"my-classifier in shadow"}'
```

Publishing refuses the snapshot, and nothing changes, if the version is not registered or is
deprecated, a stage is not in the manifest, `config` does not match `config_schema`, a parallel
group has a guardrail that is not `parallel_safe`, or a live gateway does not have the version
installed. Gateways pick the new snapshot up within seconds. Watch
`guardrail_decisions_total{id="my-classifier",mode="shadow"}` (or `GET /cp/v1/analytics/guardrails`),
then `PATCH` the assignment to `{"mode": "enforce"}` and publish again. In production a second
admin key approves the publish. If something goes wrong, `POST .../rollback` to the previous version.

With `CONFIG_SOURCE=file`, add the same assignment JSON to
`services/guardrail-gateway/config/snapshots/<env>.json` instead. The gateway reloads it within 30 s
and keeps the last good snapshot if the new one does not compile.

Scopes are `global`, `tenant` (`scope_id: "acme"`) and `agent` (`scope_id: "acme/support-bot"`).
The most specific scope wins for each guardrail id, so a disabled tenant assignment turns off
a guardrail that is enabled globally.
