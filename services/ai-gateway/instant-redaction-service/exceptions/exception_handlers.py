import logging

from fastapi import Request
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse

from exceptions import BaseError

logger = logging.getLogger(__name__)


async def handle_base_error_exception(request: Request, exc: BaseError):
    logger.error("BaseError at %s: %s", request.url, exc, exc_info=True)
    return JSONResponse(status_code=exc.status_code, content={"error": str(exc)})


async def handle_validation_exception(request: Request, exc: RequestValidationError):
    error = exc.errors()[0]
    field_name = ".".join(str(loc) for loc in error["loc"] if isinstance(loc, str))

    if error["type"] == "missing":
        message = f"Field '{field_name}' is mandatory"
    elif error["type"].startswith("type_error"):
        expected_type = error.get("ctx", {}).get("expected_type")
        message = (
            f"Field '{field_name}' must be of type {expected_type}"
            if expected_type
            else f"Field '{field_name}' has invalid type"
        )
    else:
        message = f"Field '{field_name}': {error['msg']}"

    # Do not log exc.body: request bodies carry the text being redacted (PII).
    logger.warning("Validation error at %s: %s", request.url.path, message)
    return JSONResponse(status_code=400, content={"error": message})


async def handle_http_exception(request: Request, exc: HTTPException):
    logger.error("HTTPException at %s: %s", request.url, exc.detail, exc_info=True)
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        content = exc.detail
    else:
        content = {"error": str(exc.detail)}
    return JSONResponse(status_code=exc.status_code, content=content)


async def handle_global_exception(request: Request, exc: Exception):
    logger.error("Unhandled exception at %s: %s", request.url, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error. Please try again later."},
    )
