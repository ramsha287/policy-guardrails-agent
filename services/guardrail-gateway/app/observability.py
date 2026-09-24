"""Metrics (Prometheus), tracing (OpenTelemetry) and JSON logging.

Tracing is a no-op unless OTEL_EXPORTER_OTLP_ENDPOINT is set, so tests and local runs need
no collector.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from prometheus_client import Counter, Gauge, Histogram

from app.gateway.middleware import request_id_var, trace_id_var

try:  # OpenTelemetry is optional at runtime.
    from opentelemetry import trace as _otel_trace

    _tracer = _otel_trace.get_tracer("guardrail-gateway")
except ImportError:  # pragma: no cover
    _otel_trace = None
    _tracer = None

LATENCY_BUCKETS = (5, 10, 25, 50, 100, 200, 300, 500, 800, 1000, 2000, 5000)

REQUESTS = Counter("guardrail_requests_total", "Guard requests", ["stage", "decision"])
REQUEST_LATENCY = Histogram(
    "guardrail_request_latency_ms", "End-to-end guard latency (ms)", ["stage"], buckets=LATENCY_BUCKETS
)
DECISIONS = Counter("guardrail_decisions_total", "Per-guardrail decisions", ["id", "stage", "decision", "mode"])
GUARDRAIL_LATENCY = Histogram(
    "guardrail_latency_ms", "Per-guardrail latency (ms)", ["id", "stage"], buckets=LATENCY_BUCKETS
)
GUARDRAIL_ERRORS = Counter("guardrail_errors_total", "Guardrail errors and timeouts", ["id", "stage", "kind"])
OPA_DENY = Counter("opa_deny_total", "Requests denied by OPA", ["stage"])
PROXY_REQUESTS = Counter("guardrail_proxy_requests_total", "Proxy-mode chat completions", ["status", "outcome"])
RATE_LIMITED = Counter("guardrail_rate_limited_total", "Requests refused by the per-key rate limit", ["tenant_id"])
AUDIT_DROPPED = Counter("audit_events_dropped_total", "Audit events dropped because the queue was full")
AUDIT_WRITTEN = Counter("audit_events_written_total", "Audit events written")
AUDIT_SPOOLED = Counter("audit_events_spooled_total", "Audit events written to the disk spool instead of Postgres")
CONTROL_PLANE_REACHABLE = Gauge("guardrail_control_plane_reachable", "1 if the last control-plane fetch answered")
CONFIG_LAST_SYNC = Gauge("guardrail_config_last_sync_timestamp_seconds", "Last time the control plane answered a fetch")
SNAPSHOT_LOADED = Gauge("guardrail_snapshot_loaded", "1 while a guardrail snapshot is loaded (0 = refusing traffic)")
AUDIT_SPOOL_BYTES = Gauge("audit_spool_bytes", "Bytes of audit events waiting in the disk spool")


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as s:
        for k, v in attributes.items():
            if v is not None:
                s.set_attribute(k, v)
        yield s


def setup_tracing(app: Any, endpoint: str | None, service_name: str = "guardrail-gateway") -> None:
    if not endpoint:
        return
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logging.getLogger(__name__).warning("OpenTelemetry packages missing; tracing disabled")
        return
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True)))
    _otel_trace.set_tracer_provider(provider)  # type: ignore[union-attr]
    FastAPIInstrumentor.instrument_app(app)
    HTTPXClientInstrumentor().instrument()  # propagates traceparent to ai-gateway and OPA


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if rid := request_id_var.get():
            payload["request_id"] = rid
        if tid := trace_id_var.get():
            payload["trace_id"] = tid
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # httpx logs full URLs at INFO; keep it quiet.
    logging.getLogger("httpx").setLevel(logging.WARNING)
