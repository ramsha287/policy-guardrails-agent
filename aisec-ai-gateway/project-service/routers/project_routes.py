import logging
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from dependencies import get_project_service, get_session
from exceptions import ServiceUnavailableError
from schemas.error_schema import ErrorResponse
from schemas.project_schema import (
    CreatedResponse,
    HealthResponse,
    MessageResponse,
    ProjectCreate,
    ProjectResponse,
    ProjectUpdate,
)
from services.project_service import ProjectService
from utils.constants import ALLOWED_ENTITIES

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Projects"])


@router.get("/health", response_model=HealthResponse)
async def health_check(session: AsyncSession = Depends(get_session)):
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error("Health check failed: %s", exc)
        raise ServiceUnavailableError("Database unavailable")
    return HealthResponse(status="ok")


@router.get("/entities")
async def get_supported_entities():
    return {"entities": ALLOWED_ENTITIES}


@router.post(
    "/",
    status_code=201,
    response_model=CreatedResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Project already exists or invalid data"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def create_project(
    data: ProjectCreate,
    service: ProjectService = Depends(get_project_service),
):
    return await service.create_project(data)


@router.get(
    "/",
    response_model=List[ProjectResponse],
    responses={500: {"model": ErrorResponse, "description": "Internal server error"}},
)
async def get_all_projects(service: ProjectService = Depends(get_project_service)):
    return await service.get_all_projects()


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid project ID format"},
        404: {"model": ErrorResponse, "description": "Project not found"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def get_project(
    project_id: str,
    service: ProjectService = Depends(get_project_service),
):
    return await service.get_project(project_id)


@router.put(
    "/{project_id}",
    response_model=MessageResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid project ID, data, or duplicate name"},
        404: {"model": ErrorResponse, "description": "Project not found"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def update_project(
    project_id: str,
    data: ProjectUpdate,
    service: ProjectService = Depends(get_project_service),
):
    return await service.update_project(project_id, data)


@router.delete(
    "/{project_id}",
    response_model=MessageResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid project ID format"},
        404: {"model": ErrorResponse, "description": "Project not found"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def delete_project(
    project_id: str,
    service: ProjectService = Depends(get_project_service),
):
    return await service.delete_project(project_id)
