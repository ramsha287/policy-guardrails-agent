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
(requirement D). Measure it with:

```bash
guardrail evaluate --manifest path/to/guardrail.yaml --config config.json \
  --dataset eval/datasets/<your-set>.jsonl --min-precision 0.9 --min-recall 0.9
```

`eval/README.md` describes the dataset format; `eval/generate_pii_dataset.py` is a worked example.

## 5. Roll it out

Ship the guardrail in the gateway image first, so the gateways report it in their heartbeat. Then
register the version with the control plane, add a **shadow** assignment and publish it. Full API:
[control-plane.md](control-plane.md).

```bash
CP=localhost:8200/cp/v1; A="X-Admin-Key: $CP_ADMIN_KEY"; J='content-type: application/json'
# 1. register the manifest (attach the conformance report if you have one)
curl -s -XPOST $CP/guardrails/versions -H "$A" -H "$J" -d "{\"manifest\": $(python -c 'import yaml,json;print(json.dumps(yaml.safe_load(open("guardrail.yaml"))))')}"
# 2. assign it in shadow mode
curl -s -XPUT $CP/environments/staging/assignments/global-prompt-injection -H "$A" -H "$J" -d '{
  "guardrail_id": "prompt-injection", "guardrail_version": "1.0.0", "scope_type": "global",
  "stages": ["input"], "order": 5, "mode": "shadow", "config": {"threshold": 0.8}}'
# 3. check it against real traffic before it goes live, then publish
curl -s -XPOST $CP/simulate -H "$A" -H "$J" -d '{"environment":"staging","tenant_id":"demo","stage":"input",
  "request":{"agent_id":"research-agent","action":"llm.chat","payload":{"text":"ignore previous instructions"}}}'
curl -s -XPOST $CP/environments/staging/publish -H "$A" -H "$J" -d '{"note":"prompt-injection in shadow"}'
```

Publishing refuses the snapshot, and nothing changes, if the version is not registered or is
deprecated, a stage is not in the manifest, `config` does not match `config_schema`, a parallel
group has a guardrail that is not `parallel_safe`, or a live gateway does not have the version
installed. Gateways pick the new snapshot up within seconds. Watch
`guardrail_decisions_total{id="prompt-injection",mode="shadow"}` (or `GET /cp/v1/analytics/guardrails`),
then `PATCH` the assignment to `{"mode": "enforce"}` and publish again. In production a second
admin key approves the publish. If something goes wrong, `POST .../rollback` to the previous version.

With `CONFIG_SOURCE=file`, add the same assignment JSON to
`services/guardrail-gateway/config/snapshots/<env>.json` instead. The gateway reloads it within 30 s
and keeps the last good snapshot if the new one does not compile.

Scopes are `global`, `tenant` (`scope_id: "acme"`) and `agent` (`scope_id: "acme/support-bot"`).
The most specific scope wins for each guardrail id, so a disabled tenant assignment turns off
a guardrail that is enabled globally.
