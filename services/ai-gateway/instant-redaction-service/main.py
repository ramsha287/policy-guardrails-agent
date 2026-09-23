from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from clients.project_client import close_project_client, open_project_client
from config import get_settings
from exceptions import BaseError
from exceptions.exception_handlers import (
    handle_base_error_exception,
    handle_global_exception,
    handle_http_exception,
    handle_validation_exception,
)
from routers import redaction_routes
from services.redaction_service import warmup_engines
from utils.logger import setup_logging
from utils.request_context import RequestContextMiddleware
from utils.tracing import setup_tracing

settings = get_settings()
setup_logging(settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await open_project_client()
    warmup_engines()
    try:
        yield
    finally:
        await close_project_client()


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(BaseError, handle_base_error_exception)
    app.add_exception_handler(RequestValidationError, handle_validation_exception)
    app.add_exception_handler(HTTPException, handle_http_exception)
    app.add_exception_handler(Exception, handle_global_exception)


def register_routers(app: FastAPI) -> None:
    app.include_router(redaction_routes.router, prefix="/ai-gateway/redact/api")


def create_app() -> FastAPI:
    app = FastAPI(title="Instant Redaction Service", lifespan=lifespan)

    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)
    register_routers(app)
    setup_tracing(app)
    return app


app = create_app()
