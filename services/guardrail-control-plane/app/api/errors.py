from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse

from ..domain.rbac import Forbidden
from ..errors import NotFound, StateConflict, ValidationFailed
from ..store.base import Conflict

logger = logging.getLogger(__name__)


def register(app: FastAPI) -> None:
    @app.exception_handler(Forbidden)
    async def _forbidden(_: Request, exc: Forbidden) -> JSONResponse:
        return JSONResponse(status_code=403, content={"error": str(exc)})

    @app.exception_handler(NotFound)
    async def _not_found(_: Request, exc: NotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"error": str(exc)})

    @app.exception_handler(ValidationFailed)
    async def _invalid(_: Request, exc: ValidationFailed) -> JSONResponse:
        return JSONResponse(
            status_code=422, content={"error": str(exc), "errors": exc.errors, "warnings": exc.warnings}
        )

    @app.exception_handler(StateConflict)
    @app.exception_handler(Conflict)
    async def _conflict(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=409, content={"error": str(exc)})

    @app.exception_handler(HTTPException)
    async def _http(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.detail}, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _request_invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        errs = [f"{'.'.join(str(p) for p in e.get('loc', []) if p != 'body')}: {e.get('msg')}" for e in exc.errors()]
        return JSONResponse(status_code=422, content={"error": "invalid request", "errors": errs})

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled error: %s", exc.__class__.__name__, exc_info=exc)
        return JSONResponse(status_code=500, content={"error": "Internal server error"})
