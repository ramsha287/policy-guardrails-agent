# ai-gateway changes for the guardrail platform

These are the changes the `ai-gateway-pii` adapter needs from the existing AI Security
Gateway (plan section 6). All of them are additive. Existing clients of `/text`, `/file`
and the project APIs see no change.

| # | Service | Change | Status |
| --- | --- | --- | --- |
| 1 | instant-redaction | `POST /text?include_findings=true` also returns `redacted`, `findings[]` (`entity_type`, `start`, `end`, `score`) and `offsets_basis` | **Done** (this PR) |
| 2 | instant-redaction | `POST /text/batch` (up to 100 items, findings always included) for retrieval chunks | **Done** (phase 3) |
| 3 | instant-redaction | `POST /json[?include_findings=true]` redacts every string value; findings carry a JSON path such as `$.rows[0].email` | **Done** (phase 3) |
| 4 | both | Accept `X-Request-ID` and `traceparent` and put `trace_id` in logs; optional OpenTelemetry spans when `OTEL_EXPORTER_OTLP_ENDPOINT` is set | **Done** |
| 5 | instant-redaction | Cache project config (`PROJECT_CACHE_TTL_SECONDS`, default 60). project-service publishes changes on Redis `ai-gateway:project-changed`, which evicts entries immediately | **Done** (phase 3) |
| 6 | instant-redaction | Presidio warm-up at start-up (already present) plus `GET /ready`, which returns 503 until the engines are loaded | **Done** |
| 7 | both | Stop logging request bodies on validation errors (they carry the text being redacted) | **Done** |
| 8 | project-service | API-key `scope` so the engine's key is `service` and rate-limited separately | **Done** (phase 4) |
| 9 | project-service | `hash` redaction as HMAC-SHA256 with a per-project secret | **Done** (phase 4) |
| 10 | both | `GET /version` | **Done** |

## 1. Findings on `/text`

```http
POST /ai-gateway/redact/api/text?include_findings=true
X-API-Key: gw_...
{"text": "Mail jane.doe@example.com", "project_id": "<uuid>"}
```

```json
{
  "redacted_text": "Mail [EMAIL_ADDRESS]",
  "redacted": true,
  "findings": [{"entity_type": "EMAIL_ADDRESS", "start": 5, "end": 25, "score": 1.0}],
  "offsets_basis": "normalized_text"
}
```

- Offsets refer to the text **after** `normalize_input_for_presidio`: trimmed lines joined with
  `" \n "`. That is also the text `redacted_text` is built from.
- For custom regex patterns, `entity_type` is the pattern's `redaction` label without the
  brackets, for example `EMPLOYEE_ID`.
- Matched values are never returned or logged.
- Without the query flag, the response is `{"redacted_text": ...}` exactly as before
  (`response_model_exclude_none`).

Code: `RedactionService.redact_text_detailed()` and `_analyze_and_redact()` in
`services/redaction_service.py`. `redact_text()` and every file path keep their old behaviour.

## Phase 3 changes

- **Presidio no longer blocks the event loop.** All analysis (text, batch, JSON, CSV, image and
  PDF) runs in a bounded thread pool (`ANALYZER_WORKERS`, default 4).
- **No shared-registry race.** Custom regex recognizers are passed per call as
  `ad_hoc_recognizers`, not added to and removed from the analyzer's global registry. Two
  projects with different patterns can no longer see each other's patterns when requests
  overlap (covered by a test). `utils/recognizer_utils.py` is no longer used.
- **JSON redaction keeps clean strings byte-for-byte.** Only strings with findings are replaced.
  Before, every string was rewritten with normalized whitespace.
- **Tests:** `instant-redaction-service/tests` runs against real Presidio and en_core_web_lg in CI
  (the `ai-gateway` job), with project-service and API keys faked.

## Phase 4 changes

### 8. API-key scope and rate limits

- project-service: `api_keys.scope` is `client` (default) or `service`. Migration
  `0004_api_key_scope.py` adds the column, and every existing key becomes `client`. Create the
  guardrail engine's key with `"scope": "service"`. The platform's bootstrap already does this.
- instant-redaction: each key gets a token bucket for its scope, set by
  `RATE_LIMIT_CLIENT_PER_MINUTE` (default 600) and `RATE_LIMIT_SERVICE_PER_MINUTE` (default 0,
  which means unlimited). Over the limit, the service answers **429** with `Retry-After`. Limits are
  per process, so with N replicas the effective limit is N times higher.
- **Deploy order:** run project-service migration `0004` **before** deploying the new
  instant-redaction service. The service selects `scope` from `api_keys` and fails without the
  column.

### 9. Keyed `hash` redaction

- `hash` mode is now HMAC-SHA256. Each project uses its own key, derived from `HASH_SECRET` and the
  project id, so the same value hashes differently in two projects. The hash can no longer be
  reversed by hashing guesses without the secret.
- **Breaking for anyone who stores or compares hashes.** Values hashed before the upgrade will not
  match values hashed after it. Re-hash stored values, or keep comparing old values separately.
- If `HASH_SECRET` is not set, the service keeps the old unkeyed SHA-256 behaviour (and logs a
  warning). Set it in every environment, keep it in your secret store, and do not rotate it
  casually: rotating it changes every hash.

## Still open

- **Redaction service reads `api_keys` directly.** It shares that table with project-service,
  and now reads `scope` from it too. Moving key validation behind a project-service endpoint is
  planned for phase 5.
- The project-service README still mentions MongoDB and Consul. The code uses PostgreSQL.
