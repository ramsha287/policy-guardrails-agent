import re
import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
# W3C trace id from an incoming `traceparent` header (set by the guardrail gateway), so logs
# from both services can be joined on one trace.
trace_id_var: ContextVar[str | None] = ContextVar("trace_id", default=None)

_TRACEPARENT_RE = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        match = _TRACEPARENT_RE.match(request.headers.get("traceparent", ""))
        token = request_id_var.set(request_id)
        trace_token = trace_id_var.set(match.group(1) if match else None)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
            trace_id_var.reset(trace_token)
        response.headers["X-Request-ID"] = request_id
        return response
