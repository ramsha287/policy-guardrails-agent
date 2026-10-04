"""A tiny MCP server (Streamable HTTP, JSON responses) for trying the mcp connector.

    python examples/discovery/mcp_demo_server.py [--port 8765]

It serves the tools in tools.json next to this file and re-reads the file on every request, so
you can simulate a "rug pull": edit a tool's description, run the connector again, and the
inventory opens a `tool_definition_changed` finding. Standard library only; no tool is executable
(tools/call answers an error), because the connector only ever lists tools.
"""

from __future__ import annotations

import argparse
import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOOLS = Path(__file__).resolve().parent / "tools.json"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:  # quiet
        return

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        try:
            msg = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        method, rid = msg.get("method"), msg.get("id")
        if rid is None:  # a notification
            self.send_response(202)
            self.end_headers()
            return None
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "crm-demo", "version": "1.0.0"},
            }
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": result}, session=str(uuid.uuid4()))
        if method == "tools/list":
            tools = json.loads(TOOLS.read_text(encoding="utf-8"))
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}})
        return self._send(
            200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"{method} not supported"}}
        )

    def _send(self, status: int, body: dict, session: str | None = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if session:
            self.send_header("Mcp-Session-Id", session)
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8765)
    a = p.parse_args()
    print(f"MCP demo server on http://{a.host}:{a.port}/mcp (tools from {TOOLS})", flush=True)
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
