# Gate 1: is the MVP ready?

The [platform proposal](https://claude.ai/code/artifact/8ff001c0-15f0-4725-a362-10ec3d3bd45c)
ends the MVP at a measurable gate with three criteria. This page says how to measure each one,
what this repository provides for it, and what has to happen outside it.

| Criterion | Measured with | Where |
| --- | --- | --- |
| Fast path adds **under 15 ms at p99** | `python -m app.bench` against a real OPA | this repo ([below](#1-fast-path-latency)) |
| **Shadow agents found** in the pilot environment | discovery connectors on the pilot | this repo ([below](#2-shadow-agents-in-the-pilot)) |
| Exfiltration **attack success under 5%** | an adversarial evaluation of a staging gateway | your security team ([below](#3-exfiltration-attack-success)) |

## 1. Fast-path latency

The fast path is a low-risk request: identity, context, descriptors, session state, risk v2, OPA,
the in-process guardrails, the decision table. Advisors and verification don't run on it (they
only run in the uncertain band). Remote guardrails like `ai-gateway-pii` are excluded on purpose:
the gate is the overhead *on top of* the content guardrails you already run.

```bash
opa run --server --skip-version-check --addr 127.0.0.1:8181 policies/guardrails/authz.rego &
cd services/guardrail-gateway
python -m app.bench --n 5000 --profile content --opa-url http://127.0.0.1:8181 --report bench.json --fail-over-budget
```

| Option | Meaning |
| --- | --- |
| `--profile core` | only the `noop` guardrail: the platform's own overhead |
| `--profile content` | adds `secrets` and `prompt-injection`, enforced (default) |
| `--opa-url` | the real policy call; without it policy is in-process and the report says it isn't a gate number |
| `--concurrency N` | N requests in flight on one process: measures saturation, for sizing replicas |
| `--fail-over-budget` | exit 1 when p99 is over `--budget-ms` (15), or when run without `--opa-url` |

**Where to measure.** The budget is for the gateway next to OPA on Linux, as in CI and on the
cluster. Two things on a laptop add network time that isn't the platform's:

- **`localhost` on Windows** often resolves to IPv6 (`::1`) first and falls back, which costs about
  40 ms per request. Always pass `127.0.0.1`.
- **Docker Desktop (Windows, macOS)** runs containers in a VM, and every request from the host to a
  published port is relayed. Against the Compose stack's OPA, a measured Windows laptop gave p50
  54 ms with `localhost`, 13 ms with `127.0.0.1`, and 6 ms from inside the Docker network. OPA's own
  evaluation was 0.17 ms, and the platform's overhead without OPA was 0.3 ms.

On Docker Desktop, get the closest number by running the benchmark inside the gateway container,
next to OPA. Treat it as indicative, not as the gate:

```bash
docker compose exec guardrail-gateway python -m app.bench --n 5000 --profile content --opa-url http://opa:8181
```

To see how much of the time is OPA's evaluation rather than the network, add `?metrics=true` to an
OPA query and read `timer_rego_query_eval_ns`.

What it reports: p50/p95/p99/max per stage and overall, the outcomes and risk bands (all `allow`
and `low`, so you know it measured the fast path), `throughput_rps`, and `within_budget` (only
with `--opa-url`; otherwise `null`, because it isn't a gate measurement).

Reference run (development container, Python 3.11, OPA 1.4.2 on localhost, 2,000 requests,
sequential):

| Profile | p50 | p95 | p99 |
| --- | --- | --- | --- |
| `core` | 1.9 ms | 2.9 ms | 4.2 ms |
| `content` | 2.2 ms | 3.2 ms | 4.4 ms |
| `content`, no OPA hop | 0.5 ms | 0.8 ms | 1.1 ms |

Most of the time is the OPA round trip. With 16 requests in flight on one process the p99 rises
to about 90 ms: a gateway replica is one event loop, and past its throughput (a few hundred
requests per second per core here) requests queue. Size replicas so each stays well below its
`throughput_rps`, and measure on your own hardware: the CI `latency` job runs the same benchmark,
report-only, because shared runners are noisy.

## 2. Shadow agents in the pilot

[Discovery](discovery.md) finds agents nobody registered. For the gate, connect the pilot
environment's sources (the gateway's audit log, Kubernetes, DNS query logs, the model providers'
admin APIs, MCP servers) and check that the **Agent inventory** lists its shadow agents with
evidence and an owner guess. [testing-discovery.md](testing-discovery.md) walks through it.

Since phase 9, open findings also reach the gateways: a registered agent with an open
`unmanaged_agent` finding gets an `AGENT_FINDING` risk signal, and calling a tool whose definition
changed since it was approved gets `TOOL_DEFINITION_CHANGED`
([details](discovery.md#findings-feed-the-gateways-risk)).

## 3. Exfiltration attack success

The gate asks: when an agent is manipulated (for example by instructions planted in a document it
reads) into sending sensitive data out, how often does the gateway let it through? Measure this
against a **staging** gateway with an established adversarial evaluation framework (the proposal
names AgentDojo-style tasks with adaptive attackers), run by your security team under your own
rules of engagement. This repository doesn't ship that harness.

What makes the gateway resist it, all in this repository and testable on their own:

- **Session taint and data labels.** After untrusted content (retrieved documents, external tool
  results) the session is tainted; after sensitive data it is labelled `holds:PII` or
  `holds:CONFIDENTIAL`. A later external write gets `SENSITIVE_THEN_EXTERNAL` and
  `TAINTED_SESSION`, whatever the agent was persuaded to do ([contextual decisions](contextual-decisions.md)).
- **Verification.** High risk asks the user or a reviewer; the attacker can't answer for them.
- **Content guardrails.** `ai-gateway-pii` redacts or blocks PII sent to external tools; `secrets`
  redacts credentials; `prompt-injection` drops or escalates content with injected instructions.
- **Advisors**, once calibrated, can only add risk or ask for verification.

Report the result with the configuration it was measured on (`RISK_MODE=enforce`, the snapshot
version, the advisors), and re-run it whenever those change.

## Calibrating the local advisor

The local advisor ships with hand-set starter weights. Before enforcing it, calibrate it on what
your reviewers and users decided ([advisors.md](advisors.md#calibrating-the-local-advisor)):

The two steps use **different services' CLIs**. `advisor-training-set` is a control-plane command
(the gateway's `app.cli` doesn't have it), and calibration runs in the gateway:

```bash
# 1. control plane (needs AUDIT_DSN): features of requests advisors saw, labelled by people's decisions
cd services/guardrail-control-plane
python -m app.cli advisor-training-set --out ../../advisor-set.jsonl --days 30
#    or on the Compose stack, where AUDIT_DSN is already set:
#    docker compose exec guardrail-control-plane python -m app.cli advisor-training-set --out /tmp/advisor-set.jsonl --days 30
#    docker compose cp guardrail-control-plane:/tmp/advisor-set.jsonl advisor-set.jsonl

# 2. gateway: fit, hold out 20%, report AUC, precision/recall and calibration next to today's weights
cd ../guardrail-gateway
python -m app.advise.calibrate --data ../../advisor-set.jsonl --out local-v2.json --report calibration.json --min-auc 0.75
```

The set only contains requests that an advisor answered **and a person then decided** (a reviewer
in the review queue, or the user in a confirmation). On a fresh stack it has 0 rows: send some
elevated-band requests and decide the held ones first.
