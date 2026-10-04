"""Guards for connectors: where credentials come from and where requests may go.

Credentials: a connector config names an environment variable (`*_env` keys). Only names starting
with DISCOVERY_SECRET_ are accepted, so a connector can never be pointed at INTERNAL_TOKEN,
REVIEW_ENCRYPTION_KEY or a database DSN and made to send it somewhere. Values are read when the
connector runs and never stored, logged or returned by the API.

Destinations: connectors call URLs from their config (Kubernetes API, MCP servers, an OpenAI-
compatible admin API, a log URL). Cloud metadata services, loopback, link-local, multicast and
unspecified addresses are refused, so a connector can't be used to read the control plane's own
instance credentials or its internal endpoints. Private (RFC 1918) addresses are allowed: in-cluster
APIs and internal MCP servers live there; the narrower rule is that only platform admins can create
or change connectors. Redirects are never followed. The check resolves the name before the request,
so DNS rebinding between check and request is not covered: keep connector egress behind a
NetworkPolicy as well (the Helm chart's `networkPolicy.externalEgressCIDRs`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
from collections.abc import Mapping
from urllib.parse import urlsplit

from .model import ConnectorError, Resolver, default_resolver

SECRET_ENV_RE = re.compile(r"^DISCOVERY_SECRET_[A-Z0-9_]{1,64}$")

# Cloud instance metadata endpoints (AWS/GCP/Azure/OpenStack/Alibaba) and their IPv6 forms.
METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),  # ECS task metadata
        ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
        ipaddress.ip_address("fd00:ec2::254"),
    }
)
METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata", "instance-data"})


def secret_reader(env: Mapping[str, str] | None = None):
    source = os.environ if env is None else env

    def read(name: str) -> str:
        if not SECRET_ENV_RE.fullmatch(name or ""):
            raise ConnectorError(
                f"credential variable {name!r} is not allowed: use a name starting with DISCOVERY_SECRET_"
            )
        value = source.get(name)
        if not value:
            raise ConnectorError(f"{name} is not set on the control plane")
        return value

    return read


def validate_secret_name(name: str | None) -> None:
    if name is not None and not SECRET_ENV_RE.fullmatch(name):
        raise ValueError(f"{name!r}: credential variables must start with DISCOVERY_SECRET_ (A-Z, 0-9, _)")


def forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip in METADATA_IPS:
        return "a cloud metadata address"
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address"
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "a reserved address"
    return None


def url_checker(resolver: Resolver | None = None, *, allow_http: bool = False):
    resolve = resolver or default_resolver

    async def check(url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ConnectorError(f"{url!r} is not an http(s) URL")
        if parts.scheme == "http" and not allow_http:
            raise ConnectorError(f"{url!r}: plain http is refused (set DISCOVERY_ALLOW_HTTP=true for labs)")
        host = parts.hostname.lower().rstrip(".")
        if host in METADATA_HOSTS:
            raise ConnectorError(f"{host} is a cloud metadata endpoint")
        try:
            ips = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                addrs = await asyncio.get_running_loop().run_in_executor(None, resolve, host)
            except OSError as exc:
                raise ConnectorError(f"cannot resolve {host}: {exc.__class__.__name__}") from exc
            ips = [ipaddress.ip_address(a.split("%")[0]) for a in addrs]
        for ip in ips:
            why = forbidden_ip(ip)
            if why:
                raise ConnectorError(f"{host} resolves to {why} ({ip}); connectors may not call it")

    return check
