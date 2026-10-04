"""Write a Route 53 Resolver query log with fresh timestamps, for trying the dns_log connector.

    python examples/discovery/make_dns_log.py            # -> examples/discovery/logs/route53/demo.log

Three sources, so the inventory shows each outcome:

    i-0demoagent   resolves api.openai.com and the demo MCP server, never the gateway
                   -> a confirmed shadow agent (calls a model AND uses tools), direct traffic
    10.0.4.20      resolves api.anthropic.com AND guardrail-gateway
                   -> SDK (sidecar) mode: a probable agent, not a bypass
    10.0.4.21      resolves only api.mistral.ai
                   -> a probable agent (calls a model; no tool use seen)
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent / "logs" / "route53" / "demo.log"


def record(query: str, src: str, minutes_ago: int, instance: str | None = None) -> dict:
    at = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    rec = {
        "version": "1.100000",
        "account_id": "111122223333",
        "region": "us-east-1",
        "vpc_id": "vpc-0demo",
        "query_timestamp": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "query_name": query + ".",
        "query_type": "A",
        "query_class": "IN",
        "rcode": "NOERROR",
        "answers": [],
        "srcaddr": src,
        "srcport": "53000",
        "transport": "UDP",
    }
    if instance:
        rec["srcids"] = {"instance": instance}
    return rec


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    lines = []
    for i in range(12):
        lines.append(record("api.openai.com", "10.0.3.15", 5 + i * 7, "i-0demoagent"))
    for i in range(3):
        lines.append(record("mcp-demo", "10.0.3.15", 9 + i * 11, "i-0demoagent"))
    for i in range(6):
        lines.append(record("api.anthropic.com", "10.0.4.20", 3 + i * 9))
        lines.append(record("guardrail-gateway", "10.0.4.20", 3 + i * 9))
    for i in range(4):
        lines.append(record("api.mistral.ai", "10.0.4.21", 20 + i * 13))
    lines.append(record("example.com", "10.0.4.22", 2))  # not a model or MCP host: ignored
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(json.dumps(r) for r in lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} records to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
