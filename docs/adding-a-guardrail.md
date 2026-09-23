# Adding a guardrail

A new guardrail is a plugin plus a snapshot entry. You don't change the engine, the gateway
or OPA. `ai-gateway-pii` (remote adapter) and `noop` (local) in
`services/guardrail-gateway/app/plugins/` are working examples.

## 1. Pick a kind

| Kind | Use it for | How it runs |
| --- | --- | --- |
| `local` | Fast rule checks (regex, allow and deny lists, step limits) | A Python class in the gateway process |
| `remote` | Anything in another language or with heavy dependencies | An HTTP service implementing `POST /evaluate` and `GET /health` (generic protocol), or a custom adapter class through `entrypoint` |
| `model` | ML classifiers (prompt injection, toxicity) | Same as `remote`, deployed on its own nodes (for example GPU) |

## 2. Write the manifest (`guardrail.yaml`)

```yaml
id: prompt-injection             # kebab-case, unique
version: 1.0.0                   # semver; any change is a new version
kind: local
description: Detects prompt-injection and jailbreak attempts.
owner: ai-security
data_handling: Reads input text only; stores nothing.
stages: [input, retrieval]
decisions_emitted: [allow, block]
failure_mode: fail_closed
latency_budget_ms: 50
capabilities:
  parallel_safe: true            # never emits MODIFY, so it can share a parallel_group
entrypoint: app.plugins.prompt_injection.guardrail:PromptInjectionGuardrail
config_schema: {type: object}
```

The manifest is validated when it's loaded. Unknown keys, bad ids, MODIFY without
`emits_modify`, `parallel_safe` combined with MODIFY, and an incompatible `sdk_version` are
all rejected.

## 3. Implement it

```python
from pydantic import BaseModel, ConfigDict
from guardrail_sdk import Decision, Finding, Guardrail, GuardrailResult, Payload, SecurityContext


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")   # reject unknown keys (requirement B6)
    threshold: float = 0.8


class PromptInjectionGuardrail(Guardrail):
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

## 4. Test it

```bash
guardrail conformance --manifest path/to/guardrail.yaml --config config.json [--samples labelled.json]
```

Add unit tests next to the plugin, and a labelled set of at least 200 cases per stage
(requirement D).

## 5. Roll it out

Add an assignment to `services/guardrail-gateway/config/snapshots/<env>.json`. From phase 4,
use the control-plane API instead.

```json
{"id": "global-prompt-injection", "guardrail_id": "prompt-injection", "guardrail_version": "1.0.0",
 "scope_type": "global", "stages": ["input"], "order": 5, "mode": "shadow", "config": {"threshold": 0.8}}
```

The gateway reloads the snapshot within 30 s. If the new snapshot fails to compile (unknown
guardrail version, unsupported stage, invalid config), the gateway keeps the last good one
and reports the error on `/ready`. Watch `guardrail_decisions_total{id="prompt-injection",mode="shadow"}`,
then change `mode` to `enforce`.

Scopes are `global`, `tenant` (`scope_id: "acme"`) and `agent` (`scope_id: "acme/support-bot"`).
The most specific scope wins for each guardrail id, so a disabled tenant assignment turns off
a guardrail that is enabled globally.
