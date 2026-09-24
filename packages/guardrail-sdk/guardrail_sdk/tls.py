"""TLS and mTLS settings shared by the platform's services.

In Kubernetes the recommended way to get mutual TLS between services is a service mesh
(Linkerd: `mtls.mode=linkerd` in the Helm chart), which needs no application settings.
Without a mesh, the services do it themselves with these environment variables:

Server side (see `guardrail_sdk.serving`):
  TLS_CERT_FILE / TLS_KEY_FILE   this service's certificate and key
  TLS_CLIENT_CA_FILE             CA that client certificates must chain to; when set, the
                                 internal port requires a valid client certificate (mTLS)
  TLS_PUBLIC                     "true" to serve the public port over TLS too (default: the
                                 public port is plain HTTP behind the ingress or mesh)

Client side (outbound calls to other platform services):
  TLS_CA_FILE                    CA used to verify servers (default: system trust store)
  TLS_CLIENT_CERT_FILE / TLS_CLIENT_KEY_FILE   client certificate presented for mTLS
"""

from __future__ import annotations

import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


class TLSConfigError(ValueError):
    pass


def _file(name: str, value: str | None) -> str | None:
    if not value:
        return None
    if not Path(value).is_file():
        raise TLSConfigError(f"{name} points to {value!r}, which is not a file")
    return value


@dataclass(frozen=True)
class ClientTLS:
    ca_file: str | None = None
    cert_file: str | None = None
    key_file: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ClientTLS:
        e = os.environ if env is None else env
        return cls(
            ca_file=_file("TLS_CA_FILE", e.get("TLS_CA_FILE")),
            cert_file=_file("TLS_CLIENT_CERT_FILE", e.get("TLS_CLIENT_CERT_FILE")),
            key_file=_file("TLS_CLIENT_KEY_FILE", e.get("TLS_CLIENT_KEY_FILE")),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.ca_file or self.cert_file)

    def ssl_context(self) -> ssl.SSLContext | bool:
        """For `httpx.AsyncClient(verify=...)`. True means the default trust store, no client cert."""
        if not self.enabled:
            return True
        if bool(self.cert_file) != bool(self.key_file):
            raise TLSConfigError("TLS_CLIENT_CERT_FILE and TLS_CLIENT_KEY_FILE must be set together")
        ctx = ssl.create_default_context()  # system trust store (public endpoints keep working) ...
        if self.ca_file:
            ctx.load_verify_locations(self.ca_file)  # ... plus the platform's private CA
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.cert_file and self.key_file:
            ctx.load_cert_chain(self.cert_file, self.key_file)
        return ctx


@dataclass(frozen=True)
class ServerTLS:
    cert_file: str | None = None
    key_file: str | None = None
    client_ca_file: str | None = None
    public: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ServerTLS:
        e = os.environ if env is None else env
        cfg = cls(
            cert_file=_file("TLS_CERT_FILE", e.get("TLS_CERT_FILE")),
            key_file=_file("TLS_KEY_FILE", e.get("TLS_KEY_FILE")),
            client_ca_file=_file("TLS_CLIENT_CA_FILE", e.get("TLS_CLIENT_CA_FILE")),
            public=e.get("TLS_PUBLIC", "false").lower() in ("1", "true", "yes"),
        )
        if bool(cfg.cert_file) != bool(cfg.key_file):
            raise TLSConfigError("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
        if cfg.client_ca_file and not cfg.cert_file:
            raise TLSConfigError("TLS_CLIENT_CA_FILE needs TLS_CERT_FILE/TLS_KEY_FILE (mTLS runs over TLS)")
        if cfg.public and not cfg.cert_file:
            raise TLSConfigError("TLS_PUBLIC=true needs TLS_CERT_FILE/TLS_KEY_FILE")
        return cfg

    @property
    def enabled(self) -> bool:
        return self.cert_file is not None

    @property
    def mutual(self) -> bool:
        return self.client_ca_file is not None

    def ssl_context(self, *, require_client_cert: bool) -> ssl.SSLContext:
        """Server context (used by tests and by anything not running under uvicorn)."""
        if not self.cert_file or not self.key_file:
            raise TLSConfigError("no server certificate configured")
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.cert_file, self.key_file)
        if require_client_cert:
            if not self.client_ca_file:
                raise TLSConfigError("client certificates required but TLS_CLIENT_CA_FILE is not set")
            ctx.load_verify_locations(self.client_ca_file)
            ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def uvicorn_kwargs(self, *, require_client_cert: bool) -> dict[str, object]:
        """Keyword arguments for `uvicorn.Config`."""
        if not self.enabled:
            return {}
        kw: dict[str, object] = {"ssl_certfile": self.cert_file, "ssl_keyfile": self.key_file}
        if require_client_cert and self.client_ca_file:
            kw.update(ssl_ca_certs=self.client_ca_file, ssl_cert_reqs=int(ssl.CERT_REQUIRED))
        return kw
