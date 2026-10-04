"""DNS query logs: any workload that resolves model-provider or MCP hosts.

The best single signal for shadow agents: an agent has to reach a model, and that starts with a DNS
lookup. Reads Route 53 Resolver query logs (the JSON lines AWS writes to S3 or CloudWatch; ship them
to a directory the control plane can read, or an HTTPS URL), or any JSON-lines DNS log with a field
mapping (`format: jsonl`).

Per source (EC2 instance id when the log has it, otherwise VPC + IP address) it counts lookups of
model-provider hosts (direct model access), MCP hosts and the guardrail gateway within the window.
A lookup is not a request, so these counts are reported as "lookups", separately from the gateway's
request counts. Provider lookups from a source that also looks up the gateway are SDK (sidecar) mode
traffic, not a bypass.

An IP address is a weak key: a source seen only by IP is matched to Kubernetes pods with the same IP
as a *probable* match, never merged.

Files are read only under DISCOVERY_LOG_DIR (default /var/lib/guardrail-discovery/logs); `.gz` is
supported. At most `max_mb` per run are read.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import zlib
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, Literal

import httpx
from pydantic import Field, model_validator

from .. import signatures as sig
from ..model import CollectContext, ConnectorConfig, ConnectorError, EdgeFact, EntityFact, Observation

DEFAULT_LOG_DIR = "/var/lib/guardrail-discovery/logs"


class DnsLogConfig(ConnectorConfig):
    path: str | None = Field(default=None, description="glob under DISCOVERY_LOG_DIR, e.g. route53/*.log.gz")
    url: str | None = Field(default=None, description="https URL of a JSON-lines file")
    format: Literal["route53", "jsonl"] = "route53"
    # jsonl only: dotted field paths
    query_field: str = "query_name"
    source_field: str = "srcaddr"
    time_field: str = "query_timestamp"
    instance_field: str | None = "srcids.instance"
    network_field: str | None = "vpc_id"
    window_hours: int = Field(default=24, ge=1, le=24 * 14)
    mcp_hosts: list[str] = Field(default_factory=list, description="hosts of MCP servers in your environment")
    gateway_hosts: list[str] = Field(default_factory=lambda: ["guardrail-gateway"])
    max_mb: int = Field(default=200, ge=1, le=2048)

    @model_validator(mode="after")
    def _one_source(self) -> DnsLogConfig:
        if bool(self.path) == bool(self.url):
            raise ValueError("set exactly one of path or url")
        if self.path and (self.path.startswith("/") or ".." in Path(self.path).parts):
            raise ValueError("path is a glob relative to DISCOVERY_LOG_DIR (no '/' prefix, no '..')")
        return self


class DnsLogConnector:
    kind: ClassVar[str] = "dns_log"
    title: ClassVar[str] = "DNS query logs"
    description: ClassVar[str] = (
        "Workloads resolving model-provider and MCP hosts (Route 53 Resolver query logs or any JSON-lines DNS "
        "log). The strongest signal for shadow agents."
    )
    full_snapshot: ClassVar[bool] = False
    Config: ClassVar[type[ConnectorConfig]] = DnsLogConfig

    async def collect(self, config: DnsLogConfig, ctx: CollectContext) -> AsyncIterator[Observation]:
        since = ctx.now - timedelta(hours=config.window_hours)
        budget = config.max_mb * 1024 * 1024
        if config.url:
            await ctx.check_url(config.url)
            lines = await _fetch_lines(ctx.clients.get("dns_http") or ctx.http, config.url, budget)
        else:
            root = Path(os.environ.get("DISCOVERY_LOG_DIR", DEFAULT_LOG_DIR))
            # file I/O off the event loop
            lines = await asyncio.to_thread(lambda: list(_read_files(root, str(config.path), budget, ctx)))
        sources: dict[str, dict[str, Any]] = {}
        mcp_hosts = {h.lower().rstrip(".") for h in config.mcp_hosts}
        gateway_hosts = {h.lower().rstrip(".") for h in config.gateway_hosts}
        bad = 0
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                bad += 1
                continue
            parsed = _parse(rec, config)
            if parsed is None:
                bad += 1
                continue
            host, src_ip, instance, network, at = parsed
            if at is not None and at < since:
                continue
            provider = sig.provider_for_host(host)
            is_mcp = host in mcp_hosts
            is_gateway = host in gateway_hosts or any(host.startswith(g + ".") for g in gateway_hosts)
            if not (provider or is_mcp or is_gateway):
                continue
            key = f"aws-instance:{instance}" if instance else f"netsrc:{network or '-'}/{src_ip}"
            s = sources.setdefault(
                key,
                {"ip": src_ip, "instance": instance, "network": network, "providers": {}, "mcp": {}, "gateway": 0,
                 "first": at, "last": at},
            )  # fmt: skip
            if provider:
                s["providers"][host] = s["providers"].get(host, 0) + 1
            if is_mcp:
                s["mcp"][host] = s["mcp"].get(host, 0) + 1
            if is_gateway:
                s["gateway"] += 1
            if at is not None:
                s["first"] = min(filter(None, (s["first"], at)))
                s["last"] = max(filter(None, (s["last"], at)))
        if bad:
            ctx.warn(f"{bad} log line(s) could not be parsed as {config.format}")
        for key, s in sorted(sources.items()):
            yield _source_observation(key, s, config.window_hours)


def _get(rec: dict[str, Any], dotted: str | None) -> Any:
    if not dotted:
        return None
    cur: Any = rec
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _parse(
    rec: dict[str, Any], config: DnsLogConfig
) -> tuple[str, str, str | None, str | None, datetime | None] | None:
    if config.format == "route53":
        q, src, t = rec.get("query_name"), rec.get("srcaddr"), rec.get("query_timestamp")
        inst, net = _get(rec, "srcids.instance"), rec.get("vpc_id")
    else:
        q, src, t = _get(rec, config.query_field), _get(rec, config.source_field), _get(rec, config.time_field)
        inst, net = _get(rec, config.instance_field), _get(rec, config.network_field)
    if not isinstance(q, str) or not isinstance(src, str):
        return None
    at = None
    if isinstance(t, str):
        try:
            at = datetime.fromisoformat(t.replace("Z", "+00:00"))
            at = at if at.tzinfo else at.replace(tzinfo=UTC)
        except ValueError:
            at = None
    return (
        q.lower().rstrip("."),
        src,
        inst if isinstance(inst, str) else None,
        net if isinstance(net, str) else None,
        at,
    )


def _read_files(root: Path, pattern: str, budget: int, ctx: CollectContext) -> Iterator[str]:
    root = root.resolve()
    files = sorted(p for p in root.glob(pattern) if p.is_file())
    if not files:
        raise ConnectorError(f"no files match {pattern} under {root}")
    used = 0
    for f in files:
        real = f.resolve()
        if root not in real.parents:  # symlink pointing outside the log directory
            ctx.warn(f"skipped {f.name}: outside DISCOVERY_LOG_DIR")
            continue
        opener = gzip.open if real.suffix == ".gz" else open
        with opener(real, "rt", encoding="utf-8", errors="replace") as fh:  # type: ignore[operator]
            for line in fh:
                used += len(line)
                if used > budget:
                    ctx.warn(f"stopped after {budget // (1024 * 1024)} MB (max_mb)")
                    return
                if line.strip():
                    yield line


async def _fetch_lines(http: httpx.AsyncClient, url: str, budget: int) -> list[str]:
    try:
        async with http.stream("GET", url, follow_redirects=False, timeout=60.0) as resp:
            if resp.status_code != 200:
                raise ConnectorError(f"log URL answered {resp.status_code}")
            data = bytearray()
            async for chunk in resp.aiter_bytes():
                data.extend(chunk)
                if len(data) > budget:
                    break
    except httpx.HTTPError as exc:
        raise ConnectorError(f"log URL unreachable: {exc.__class__.__name__}") from exc
    raw = bytes(data[:budget])
    if raw[:2] == b"\x1f\x8b":
        # Bounded: a small gzip must not expand past the budget (decompression bomb).
        d = zlib.decompressobj(wbits=31)
        try:
            raw = d.decompress(raw, budget)
        except zlib.error as exc:
            raise ConnectorError("log URL: not valid gzip") from exc
    return [ln for ln in raw.decode("utf-8", errors="replace").splitlines() if ln.strip()]


def _source_observation(key: str, s: dict[str, Any], hours: int) -> Observation:
    lookups = sum(s["providers"].values())
    signals: set[str] = set()
    if lookups:
        signals.add("calls_model")
        # SDK (sidecar) mode calls the model directly after the gateway checked the input, so
        # provider lookups count as a bypass only from sources that never look up the gateway.
        if not s["gateway"]:
            signals.add("direct_model_access")
    if s["mcp"]:
        signals |= {"mcp_client", "uses_tools"}
    if s["gateway"]:
        signals.add("gateway_client")
    name = s["instance"] or f"{s['ip']}" + (f" ({s['network']})" if s["network"] else "")
    facts = [
        EntityFact(
            "self",
            "endpoint",
            name,
            [key],
            weak_keys=[f"ip:{s['ip']}"],
            signals=signals,
            direct_volume=0 if s["gateway"] else lookups,
            attrs={
                "ip": s["ip"],
                "instance": s["instance"],
                "network": s["network"],
                "provider_lookups": dict(sorted(s["providers"].items())),
                "mcp_lookups": dict(sorted(s["mcp"].items())),
                "gateway_lookups": s["gateway"],
                "first_lookup": s["first"].isoformat() if s["first"] else None,
                "last_lookup": s["last"].isoformat() if s["last"] else None,
                "window_hours": hours,
                "volume_unit": "dns_lookups",
            },
        )
    ]
    edges = []
    for host in sorted(s["providers"]):
        provider = sig.provider_for_host(host) or host
        ref = f"p:{provider}"
        if all(f.ref != ref for f in facts):
            facts.append(EntityFact(ref, "model_provider", provider, [f"provider:{provider}"]))
            edges.append(EdgeFact("self", ref, "calls_model", {"via": "direct"}))
    for host in sorted(s["mcp"]):
        ref = f"m:{host}"
        facts.append(EntityFact(ref, "mcp_server", host, [f"mcp-host:{host}"], weak_keys=[f"mcp-host:{host}"]))
        edges.append(EdgeFact("self", ref, "uses_tool"))
    return Observation(
        kind="dns.model_traffic",
        source_ref=key,
        entities=facts,
        edges=edges,
        attrs={"provider_lookups": lookups, "mcp_lookups": sum(s["mcp"].values()), "gateway_lookups": s["gateway"]},
    )
