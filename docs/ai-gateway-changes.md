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
| 8 | project-service | API-key `scope` so the engine's key is `service` and rate-limited separately | Phase 4 |
| 9 | project-service | `hash` redaction as HMAC-SHA256 with a per-project secret | Phase 4 |
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

## Still open

- **Unsalted `hash` mode.** A SHA-256 hash of a phone number or email can be reversed by brute
  force (change 9, phase 4).
- **Redaction service reads `api_keys` directly.** It shares that table with project-service.
  This stays for now; the plan retires it in phase 4.
- The project-service README still mentions MongoDB and Consul. The code uses PostgreSQL.
