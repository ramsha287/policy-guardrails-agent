"""Run a service on a public port and, optionally, a separate internal port for service-to-service calls.

  PORT            public port (agents, the console, probes). Plain HTTP unless TLS_PUBLIC=true.
  INTERNAL_PORT   when set, internal routes (for example /cp/v1/internal or /internal) are only
                  served on this port, over TLS, and with TLS_CLIENT_CA_FILE set, only to callers
                  presenting a client certificate (mTLS). When unset, everything is served on PORT
                  as before and internal routes rely on the shared X-Internal-Token alone.

Both listeners share one application instance, so one lifespan and one set of connections.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from typing import Any

from .tls import ServerTLS

logger = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class InternalRouteGuard:
    """ASGI middleware: requests for internal routes that arrive on any port except `internal_port` get 404.

    The port comes from the ASGI scope's `server` tuple (the listening socket), which clients
    cannot spoof, unlike the Host header.
    """

    def __init__(self, app: ASGIApp, prefixes: Sequence[str], internal_port: int) -> None:
        self.app = app
        self.prefixes = tuple(p.rstrip("/") for p in prefixes)
        self.internal_port = internal_port

    def _internal(self, path: str) -> bool:
        return any(path == p or path.startswith(p + "/") for p in self.prefixes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and self._internal(scope.get("path", "")):
            server = scope.get("server") or (None, None)
            if server[1] != self.internal_port:
                body = b'{"error":"Not Found"}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": 404,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


@dataclass(frozen=True)
class Listeners:
    host: str
    port: int
    internal_port: int | None
    tls: ServerTLS

    @classmethod
    def from_env(cls, default_port: int, env: Mapping[str, str] | None = None) -> Listeners:
        e = os.environ if env is None else env
        internal = e.get("INTERNAL_PORT")
        cfg = cls(
            host=e.get("HOST", "0.0.0.0"),  # noqa: S104 - containers listen on all interfaces
            port=int(e.get("PORT", default_port)),
            internal_port=int(internal) if internal else None,
            tls=ServerTLS.from_env(e),
        )
        if cfg.internal_port is not None and cfg.internal_port == cfg.port:
            raise ValueError("INTERNAL_PORT must differ from PORT")
        if cfg.tls.mutual and cfg.internal_port is None:
            raise ValueError(
                "TLS_CLIENT_CA_FILE (mTLS) needs INTERNAL_PORT: the public port can't require client certificates"
            )
        return cfg


def run(
    app_factory: Callable[[], ASGIApp],
    *,
    default_port: int,
    internal_prefixes: Sequence[str],
    log_config: dict[str, Any] | None = None,
) -> None:
    """Blocking entry point used by `python -m app.serve`."""
    listeners = Listeners.from_env(default_port)
    asyncio.run(serve(app_factory(), listeners, internal_prefixes, log_config=log_config))


async def serve(
    app: ASGIApp,
    listeners: Listeners,
    internal_prefixes: Sequence[str],
    *,
    log_config: dict[str, Any] | None = None,
    stop: asyncio.Event | None = None,
) -> None:
    import uvicorn

    common: dict[str, Any] = {"proxy_headers": True, "forwarded_allow_ips": "*", "log_config": log_config}
    served: ASGIApp = app
    if listeners.internal_port is not None:
        served = InternalRouteGuard(app, internal_prefixes, listeners.internal_port)

    public_tls = listeners.tls.uvicorn_kwargs(require_client_cert=False) if listeners.tls.public else {}
    public = uvicorn.Server(
        uvicorn.Config(served, host=listeners.host, port=listeners.port, lifespan="on", **public_tls, **common)
    )
    servers = [public]
    if listeners.internal_port is not None:
        internal_tls = listeners.tls.uvicorn_kwargs(require_client_cert=True)
        if not internal_tls:
            logger.warning(
                "INTERNAL_PORT %s has no TLS_CERT_FILE: internal calls are plain HTTP", listeners.internal_port
            )
        internal = uvicorn.Server(
            uvicorn.Config(
                served, host=listeners.host, port=listeners.internal_port, lifespan="off", **internal_tls, **common
            )
        )
        servers.append(internal)

    tasks = [asyncio.create_task(public.serve())]
    if len(servers) > 1:
        # The internal listener shares the app; start it once startup (lifespan) has finished.
        while not public.started and not tasks[0].done():  # noqa: ASYNC110 - uvicorn exposes no start event
            await asyncio.sleep(0.05)
        if tasks[0].done():
            await tasks[0]
            return
        tasks.append(asyncio.create_task(servers[1].serve()))
        mtls = "mTLS" if listeners.tls.mutual else ("TLS" if listeners.tls.enabled else "plain HTTP")
        logger.info("internal routes %s on port %s (%s)", list(internal_prefixes), listeners.internal_port, mtls)

    waiters: list[asyncio.Task[Any]] = list(tasks)
    if stop is not None:
        waiters.append(asyncio.create_task(stop.wait()))
    done, pending = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
    for srv in servers:  # one stopped (signal, error or `stop`): stop the other too
        srv.should_exit = True
    await asyncio.gather(*tasks, return_exceptions=True)
    for w in pending:
        if w not in tasks:
            w.cancel()
    for t in done:
        if t in tasks:
            t.result()
