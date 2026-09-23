from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from exceptions import BaseError
from exceptions.exception_handlers import (
    handle_base_error_exception,
    handle_global_exception,
    handle_validation_exception,
)
from routers import api_key_routes, project_routes
from utils.logger import setup_logging
from utils.request_context import RequestContextMiddleware

settings = get_settings()
setup_logging(settings.log_level)


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(BaseError, handle_base_error_exception)
    app.add_exception_handler(RequestValidationError, handle_validation_exception)
    app.add_exception_handler(Exception, handle_global_exception)


def register_routers(app: FastAPI) -> None:
    app.include_router(project_routes.router, prefix="/ai-gateway/project/api")
    app.include_router(api_key_routes.router, prefix="/ai-gateway/apikeys/api")


def create_app() -> FastAPI:
    app = FastAPI(title="Project Management Service")

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
    return app


app = create_app()
