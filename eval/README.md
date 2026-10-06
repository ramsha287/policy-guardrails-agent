# Guardrail evaluation

`datasets/pii_v1.jsonl` has 880 labelled, synthetic cases: 220 per stage (input, output,
retrieval, tool), half with PII and half clean. The clean cases include look-alikes such as order
numbers, versions, times and amounts. That exceeds plugin requirement D, which asks for at least
200 cases per stage.

The file comes from `generate_pii_dataset.py` with a fixed seed, so it can be regenerated exactly:

```bash
python eval/generate_pii_dataset.py
```

## Run it against the live ai-gateway

```bash
docker compose up -d
eval "$(docker compose exec -T guardrail-gateway cat /bootstrap/dev.env | grep -E '^AI_GATEWAY_(API_KEY|PROJECT_ID)=' | sed 's/^/export /')"
cd services/guardrail-gateway
PYTHONPATH=. guardrail evaluate \
  --manifest app/plugins/ai_gateway_pii/guardrail-1.1.0.yaml \
  --config ../../eval/ai-gateway-pii.config.json \
  --dataset ../../eval/datasets/pii_v1.jsonl \
  --min-precision 0.9 --min-recall 0.9 --report ../../eval-report.json
```

The report gives precision, recall, F1, p50 and p95 latency per stage. It also lists the ids of
the false negatives and false positives, so you can look them up in the dataset. The command exits
with status 1 if any stage misses a threshold, has fewer than `--min-cases` cases, or raised errors.

A case counts as **detected** when the guardrail returns MODIFY or BLOCK, or reports findings.

## The secrets set

`generate_secrets_dataset.py` builds a labelled set for the `secrets` guardrail: 220 cases per
stage, half with one credential (AWS, GitHub, Slack, OpenAI, Anthropic, Stripe, Google, JWTs,
private keys, database URLs, password assignments) and half clean look-alikes (UUIDs, git SHAs,
checksums, placeholders, masked values). It is generated on demand and **not committed**, because
it is full of credential-shaped strings that secret scanners rightly flag:

```bash
python eval/generate_secrets_dataset.py     # -> eval/datasets/secrets_v1.jsonl (git-ignored)
cd services/guardrail-gateway
PYTHONPATH=. guardrail evaluate --manifest app/plugins/secrets/guardrail.yaml \
  --dataset ../../eval/datasets/secrets_v1.jsonl --min-precision 0.95 --min-recall 0.95
```

The gateway test suite builds and checks it too (`test_secrets_meets_requirement_d_on_the_generated_set`).

There is no labelled set for `prompt-injection` in this repository: measure it in shadow mode on
your own traffic, or on a public benchmark your security team chooses.

## Adding a dataset for a new guardrail

Use the same JSON Lines format:
`{"id", "stage", "label": "clean" | "pii" | "secret" | "injection" | "detect", "payload": {...}, "entities": [...]}`
(any label other than `clean` means "should be detected"). The payload is
exactly what the gateway receives for that stage. Commit the generator script with the data.
