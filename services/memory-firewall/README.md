# memory-firewall service (:8300)

An authenticated HTTP API around the Memory Firewall library, vendored **unmodified** in
`vendor/memory-firewall` (see [vendor/VENDORED.md](vendor/VENDORED.md)). It is what the gateway's
`memory-firewall` guardrail and the control plane's `/cp/v1/memory-firewall/*` relay call.
Integration guide:
[docs/memory-firewall.md](../../docs/memory-firewall.md).

| File | Role |
| --- | --- |
| `app/firewall.py` | The integration boundary: the only module that imports the library (`guard`, `scan`) |
| `app/selftest.py` | Runs the library's checkpoint attacks (`lab.tamper.ATTACKS`) in a subprocess |
| `app/main.py` | FastAPI app: auth (`X-API-Key`), limits, routes, JSON errors and logs |
| `app/config.py` | Settings from the environment (`MEMORY_FIREWALL_*`) |
| `vendor/memory-firewall/` | The library, byte-exact from its source commit; never edit it here |

## Run

```bash
# Compose (from the repository root)
docker compose up -d --build memory-firewall

# Directly (Python 3.12)
pip install -r requirements.txt
PYTHONPATH=vendor/memory-firewall/src MEMORY_FIREWALL_API_KEY=dev-memory-firewall-key-change-me \
  MEMORY_FIREWALL_DATA_DIR=./.data uvicorn --factory app.main:create_app --port 8300
```

## Test

```bash
pip install -r requirements-dev.txt
pytest
```

The tests use the vendored library, including the five checkpoint attacks (about 10 seconds), and
check that the vendored files still match `vendor/SHA256SUMS`.
