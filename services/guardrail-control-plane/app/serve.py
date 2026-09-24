"""Entry point: `python -m app.serve`.

PORT (default 8200) serves the console, the admin API and probes. With INTERNAL_PORT set,
/cp/v1/internal/* (gateway sync, heartbeats, the review queue) is only served there, over TLS,
and with TLS_CLIENT_CA_FILE only to gateways presenting a client certificate (mTLS).
"""

from app.main import create_app
from guardrail_sdk.serving import run

if __name__ == "__main__":
    run(create_app, default_port=8200, internal_prefixes=["/cp/v1/internal"])
