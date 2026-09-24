"""Entry point: `python -m app.serve`.

PORT (default 8100) serves agents and probes. With INTERNAL_PORT set, /internal/* (the control
plane's simulation calls) is only served there, over TLS, and with TLS_CLIENT_CA_FILE only to
callers presenting a client certificate. See guardrail_sdk.serving and guardrail_sdk.tls.
"""

from app.main import create_app
from guardrail_sdk.serving import run

if __name__ == "__main__":
    run(create_app, default_port=8100, internal_prefixes=["/internal"])
