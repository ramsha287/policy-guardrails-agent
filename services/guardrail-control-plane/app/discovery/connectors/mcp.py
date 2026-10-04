"""MCP servers (active, opt-in): list each server's tools and pin their definitions.

For each configured server URL (Streamable HTTP transport) it runs `initialize`,
`notifications/initialized` and `tools/list` (following `nextCursor`), then records every tool with a
SHA-256 of its name, description and input schema. The pipeline compares the hash with the last
run: a changed definition on a server you already approved is how a "rug pull" (tool poisoning
after approval) shows up, so it opens a high-severity `tool_definition_changed` finding.

Only `tools/list` is called; no tool is ever invoked. Auth: an optional header whose value comes
from a DISCOVERY_SECRET_* variable (e.g. a bearer token for the server).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..model import CollectContext, ConnectorConfig, ConnectorError, EdgeFact, EntityFact, Observation
from ..safety import validate_secret_name

PROTOCOL_VERSION = "2025-06-18"
MAX_DESCRIPTION = 4000


class McpServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    name: str | None = None
    auth_header: str = "Authorization"
    auth_env: str | None = None  # value sent as-is, e.g. "Bearer ..." stored in DISCOVERY_SECRET_MCP_CRM
    owner: str | None = None

    @field_validator("auth_env")
    @classmethod
    def _secret(cls, v: str | None) -> str | None:
        validate_secret_name(v)
        return v


class McpConfig(ConnectorConfig):
    servers: list[McpServerConfig] = Field(min_length=1, max_length=200)


def tool_hash(tool: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"name": tool.get("name"), "description": tool.get("description"), "inputSchema": tool.get("inputSchema")},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def server_key(url: str) -> str:
    p = urlsplit(url)
    return (
        f"mcp:{p.scheme}://{(p.hostname or '').lower()}{':' + str(p.port) if p.port else ''}{p.path.rstrip('/') or '/'}"
    )


class McpConnector:
    kind: ClassVar[str] = "mcp"
    title: ClassVar[str] = "MCP servers (tools/list)"
    description: ClassVar[str] = (
        "Lists the tools of the MCP servers you name and pins a hash of each definition, so a changed tool "
        "description (a rug pull) opens a finding. Never calls a tool."
    )
    full_snapshot: ClassVar[bool] = True
    Config: ClassVar[type[ConnectorConfig]] = McpConfig

    async def collect(self, config: McpConfig, ctx: CollectContext) -> AsyncIterator[Observation]:
        http = ctx.clients.get("mcp_http") or ctx.http
        for server in config.servers:
            try:
                await ctx.check_url(server.url)
                headers = {}
                if server.auth_env:
                    headers[server.auth_header] = ctx.secrets(server.auth_env)
                info, tools = await _enumerate(http, server.url, headers)
            except ConnectorError as exc:
                ctx.warn(f"{server.name or server.url}: {exc}")
                continue
            yield _server_observation(server, info, tools)


class _Session:
    def __init__(self, http: httpx.AsyncClient, url: str, headers: dict[str, str]) -> None:
        self.http, self.url = http, url
        self.headers = {
            **headers,
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        self.next_id = 0

    async def post(self, message: dict[str, Any]) -> httpx.Response:
        try:
            return await self.http.post(
                self.url, json=message, headers=self.headers, follow_redirects=False, timeout=20.0
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(f"unreachable ({exc.__class__.__name__})") from exc

    async def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.next_id += 1
        rid = self.next_id
        resp = await self.post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        if resp.status_code in (401, 403):
            raise ConnectorError(f"{method} refused ({resp.status_code}); set auth_env for this server")
        if resp.status_code != 200:
            raise ConnectorError(f"{method} answered HTTP {resp.status_code}")
        if sid := resp.headers.get("Mcp-Session-Id"):
            self.headers["Mcp-Session-Id"] = sid
        msg = _message(resp, rid)
        if "error" in msg:
            raise ConnectorError(f"{method} failed: {str((msg['error'] or {}).get('message'))[:200]}")
        return msg.get("result") or {}


def _message(resp: httpx.Response, rid: int) -> dict[str, Any]:
    ctype = resp.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                try:
                    msg = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if isinstance(msg, dict) and msg.get("id") == rid:
                    return msg
        raise ConnectorError("no response in the event stream")
    try:
        msg = resp.json()
    except ValueError as exc:
        raise ConnectorError("response is not JSON") from exc
    if isinstance(msg, list):  # a batch
        msg = next((m for m in msg if isinstance(m, dict) and m.get("id") == rid), {})
    if not isinstance(msg, dict):
        raise ConnectorError("unexpected JSON-RPC response")
    return msg


async def _enumerate(
    http: httpx.AsyncClient, url: str, headers: dict[str, str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    s = _Session(http, url, headers)
    init = await s.request(
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "guardrail-discovery", "version": "0.8.0"},
        },
    )
    if version := init.get("protocolVersion"):
        s.headers["MCP-Protocol-Version"] = str(version)
    await s.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    if "tools" not in (init.get("capabilities") or {}):
        return init, []
    tools: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(50):
        result = await s.request("tools/list", {"cursor": cursor} if cursor else {})
        tools.extend(t for t in result.get("tools") or [] if isinstance(t, dict) and t.get("name"))
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return init, tools


def _server_observation(server: McpServerConfig, init: dict[str, Any], tools: list[dict[str, Any]]) -> Observation:
    key = server_key(server.url)
    info = init.get("serverInfo") or {}
    name = server.name or info.get("name") or urlsplit(server.url).hostname or server.url
    host = (urlsplit(server.url).hostname or "").lower()
    facts = [
        EntityFact(
            "self",
            "mcp_server",
            name,
            [key],
            weak_keys=[f"mcp-host:{host}"],  # several servers can share a host: suggest, never merge
            owner=server.owner,
            attrs={
                "url": server.url,
                "server_name": info.get("name"),
                "server_version": info.get("version"),
                "protocol_version": init.get("protocolVersion"),
                "tools": len(tools),
            },
        )
    ]
    edges = []
    for t in tools:
        tname = str(t["name"])
        ref = f"tool:{tname}"
        description = str(t.get("description") or "")
        facts.append(
            EntityFact(
                ref,
                "tool",
                f"{name}/{tname}",
                [f"{key}#{tname}"],
                attrs={
                    "definition_hash": tool_hash(t),
                    "description": description[:MAX_DESCRIPTION],
                    "annotations": t.get("annotations") or {},
                    "input_schema_keys": sorted(((t.get("inputSchema") or {}).get("properties") or {}).keys())[:50],
                },
            )
        )
        edges.append(EdgeFact("self", ref, "exposes_tool"))
    return Observation(
        kind="mcp.tools_list",
        source_ref=server.url,
        entities=facts,
        edges=edges,
        attrs={"server": name, "tools": sorted(str(t["name"]) for t in tools)[:200]},
    )
