# ai-gateway changes for the guardrail platform

These are the changes the `ai-gateway-pii` adapter needs from the existing AI Security
Gateway (plan section 6). All of them are additive. Existing clients of `/text`, `/file`
and the project APIs see no change.

| # | Service | Change | Status |
| --- | --- | --- | --- |
| 1 | instant-redaction | `POST /text?include_findings=true` also returns `redacted`, `findings[]` (`entity_type`, `start`, `end`, `score`) and `offsets_basis` | **Done** (this PR) |
| 2 | instant-redaction | `POST /text/batch` (up to 100 items) for retrieval chunks | Phase 3 |
| 3 | instant-redaction | `POST /json` for JSON bodies (tool arguments and results) | Phase 3 |
| 4 | both | Accept `X-Request-ID` and `traceparent` and put `trace_id` in logs; optional OpenTelemetry spans when `OTEL_EXPORTER_OTLP_ENDPOINT` is set | **Done** |
| 5 | instant-redaction | Cache project config (60 s TTL, invalidated from project-service over Redis) | Phase 3 |
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

## Known issues found while integrating (not changed yet)

- **Presidio runs on the event loop.** `analyzer.analyze()` is synchronous inside `async def`,
  so one large request stalls every other request on that worker. The fix is to run analysis
  in a thread pool and pass custom recognizers as `ad_hoc_recognizers`, not by mutating the
  shared registry under `temp_custom_recognizers`. Scheduled with change 5 in phase 3, with a
  load test.
- **Project fetched on every request.** Every call makes an HTTP round trip to
  project-service (change 5).
- **Unsalted `hash` mode.** SHA-256 of a phone number or email can be reversed by brute
  force (change 9).
- **Redaction service reads `api_keys` directly.** The two services share a table. This stays
  as it is for now, and the plan retires it in phase 4.
- The project-service README still mentions MongoDB and Consul. The code uses PostgreSQL.
