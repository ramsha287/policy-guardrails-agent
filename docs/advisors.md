# Advisors (phase 8)

Advisors are optional, pluggable classifiers the gateway asks **only when a request is already in
the uncertain risk band** (elevated or high). They answer one narrow, typed question and can only
make the decision stricter: add capped risk points, or ask for a person to confirm. Nothing an
advisor returns can permit a request, lower a score, or clear a verification. This is the
"intelligence layer" of the [platform proposal](https://claude.ai/code/artifact/8ff001c0-15f0-4725-a362-10ec3d3bd45c),
built so that whatever an attacker does to an advisor, the worst outcome is more friction.

The deterministic path — identity, descriptors, policy, risk v2, the decision table and
verification ([contextual decisions](contextual-decisions.md)) — is unchanged. Advisors sit between
the guardrails and the decision table and feed it two things: capped points (code `ADVISOR_RISK`)
and, optionally, a request for verification (code `ADVISOR_VERIFY`).

```
guardrails ─▶ advisors (uncertain band only) ─▶ decision table ─▶ verify / enforce
                │ add ≤ cap points, or ask to verify
                └ never permit, never lower risk
```

## The two questions

Each advisor answers one or both, about the action the agent is trying to take:

| Question | Meaning |
| --- | --- |
| `exfiltration` | Is this action likely moving sensitive data out of the organisation? |
| `injection` | Is this action likely driven by instructions from untrusted content, not the user's task? |

An answer is strictly typed: `{"label": "benign" | "suspicious" | "malicious", "confidence": 0..1,
"verify": false}`. Anything else — an extra field, a value out of range, a slow reply, an exception
— counts as **no signal**, exactly as if the advisor had not run.

## What an advisor sees (and never sees)

An advisor is asked about **derived features only**, never the request's content. The question is
built from the action descriptor, the session state, the risk assessment, and *counts and sizes* of
the content (number of URLs, bytes in a URL query string, whether an encoded blob is present, the
guardrail finding types). It carries no payload text, no tool results, no argument values, and not
even the destination host name — only its shape (is it an IP literal, how many labels, does it
look like an internal domain). So content the agent fetched can never become an instruction to the
advisor that judges acting on that content.

The agent, in turn, never sees advisor output: the response carries one aggregated `ADVISOR_RISK`
code, never which advisor answered or why. Per-advisor answers go only to the audit record.

## Providers

| Provider | Where it runs | Hosted | Use |
| --- | --- | --- | --- |
| `local` | in-process, logistic model over the features | no | always-on signal, no data leaves the gateway |
| `http` | an HTTPS endpoint you run (contract `guardrail.advisor.v1`) | yes | a vendor classifier, or the Jev pilot |
| `bedrock` | Amazon Bedrock Converse, in your account | yes | an LLM judge (1–10 s: shadow, not inline enforce) |

**local** ships with a small weights file (`app/advise/models/local-v1.json`). The weights in this
release are hand-set starting points, not trained: run `local` in **shadow** mode and calibrate it
on your own labelled traffic before enforcing. The feature vector and model format are in
`app/advise/providers/local.py`; retrain by replacing the JSON file.

**http** posts `{"schema": "guardrail.advisor.v1", "question": <question>}` and expects the typed
answer. Redirects are not followed; plain `http://` is refused unless `allow_http` is set (labs).
Credentials come from an `ADVISOR_SECRET_*` environment variable named in `auth_env`, never inline.

**bedrock** sends the question's JSON to a fixed prompt and parses exactly one JSON object back.
`boto3` is imported only when a bedrock advisor is configured.

## Configuration

`ADVISORS_JSON` is a JSON list of advisors, or an object `{"advisors": [...], "total_cap": 20,
"bands": ["elevated", "high"]}`. Empty = no advisors. Each advisor:

```json
{
  "name": "local",          // unique, [a-z0-9_-]
  "provider": "local",      // local | http | bedrock
  "mode": "shadow",         // shadow (compute + audit only) | enforce
  "cap": 10,                // max points this advisor can add (0..20)
  "timeout_ms": 200,        // a slower answer is no signal
  "allow_verify": true,     // may ask for verification
  "questions": ["exfiltration", "injection"],
  "options": {}             // provider settings (weights_path / url+auth_env / model_id)
}
```

- **Caps.** Each advisor adds at most its `cap`; all advisors together add at most `total_cap` (20).
  A `malicious` answer at confidence 1.0 is worth the full cap, `suspicious` half, `benign` nothing.
- **Bands.** Advisors run only for the `bands` listed (elevated and high by default). Low risk
  doesn't need them; critical already goes to a person.
- **Shadow vs enforce.** A shadow advisor's answer is recorded with the decision but changes
  nothing (`shadow_points` in the audit record show what it *would* have added). Pilot in shadow,
  read the [Advisors analytics](#measuring-the-pilot), then switch to enforce.

A malformed `ADVISORS_JSON`, an unknown provider, a duplicate name or a bad cap stops the gateway
at startup rather than silently disabling an advisor.

### Helm

```yaml
gateway:
  advisors: '[{"name":"local","provider":"local","mode":"shadow"}]'
  advisorSecretKeys: [ADVISOR_SECRET_JEV]   # ADVISOR_SECRET_* keys in the platform Secret
```

## Tenant data policy (hosted advisors)

A hosted advisor (`http`, `bedrock`) sends features outside the gateway, so it conflicts with the
platform's "raw text never stored, never sent" stance unless a tenant opts in. A hosted advisor
sees a tenant's request **only when the tenant allows the request's data class, and every sensitive
class the session already holds**. It is off by default.

Set it per tenant in the console (**Advisors** → *Hosted advisor data policy*), or via the API:

```bash
curl -X PUT .../cp/v1/tenants/acme/advisor-policy -H "X-Admin-Key: $K" \
  -d '{"data_classes": ["INTERNAL", "PUBLIC"]}'
```

Local advisors never leave the gateway and ignore this policy. Turning on hosted advisors for a
tenant requires every live gateway to report the `advisors_v1` capability (0.9+), the same guard
the control plane uses for agent-bound keys; the control plane refuses otherwise (422).

## Measuring the pilot

The control plane reads advisor answers back out of the audit log (they are stored in
`risk.advisors`). The console's **Advisors** page (and `GET /cp/v1/analytics/advisors`) shows, per
advisor: how often it answered vs. produced no signal, its label mix, latency, and **agreement** —
of the requests it flagged, how many the deterministic path stopped anyway. The cases that deserve
attention before enforcing are the ones an advisor flagged that were *released*: its
`flagged_released` count. An advisor is worth enforcing only when it beats the deterministic
baseline there without raising the hold rate above what reviewers can handle.

## Safety properties

- **Only tighten** (enforced in `app/advise/panel.py`, not trusted to providers).
- **Evidence first**: an advisor's opinion raises risk but can never *start* containment — only a
  deterministic signal (policy, a verifier, a threat finding) can.
- **Separate channels**: the question is built from trusted, structured fields; untrusted content
  enters only as derived counts, never as text.
- **No credentials, no tools inline**: `local` is a pure function; `http`/`bedrock` reach only
  their own endpoint.
- **Typed, capped, timed out**: anything malformed, out of range or slow is no signal, so an
  advisor outage or a prompt-injected answer can only cost a little latency, never open the gate.

Advisors are evaluated against the project's own red-team harness before being trusted in enforce
mode; see the roadmap note in [the proposal](https://claude.ai/code/artifact/8ff001c0-15f0-4725-a362-10ec3d3bd45c)
(Gate 1). That harness is run against a staging gateway, outside this repository.

To check advisors on your install, see [testing advisors](testing-advisors.md).
