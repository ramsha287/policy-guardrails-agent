from typing import List

from fastapi import APIRouter, Depends, Query

from dependencies import get_api_key_service
from schemas.api_key_schema import (
    ApiKeyCreate,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
)
from schemas.error_schema import ErrorResponse
from schemas.project_schema import MessageResponse
from services.api_key_service import ApiKeyService

router = APIRouter(tags=["API Keys"])


@router.post(
    "/",
    response_model=ApiKeyCreatedResponse,
    status_code=201,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def create_api_key(
    data: ApiKeyCreate,
    service: ApiKeyService = Depends(get_api_key_service),
):
    return await service.create_key(data)


@router.get(
    "/",
    response_model=List[ApiKeyResponse],
    responses={500: {"model": ErrorResponse, "description": "Internal server error"}},
)
async def list_api_keys(
    include_disabled: bool = Query(False, description="If true, include revoked keys"),
    service: ApiKeyService = Depends(get_api_key_service),
):
    return await service.list_keys(include_disabled=include_disabled)


@router.get(
    "/{key_id}",
    response_model=ApiKeyResponse,
    responses={
        404: {"model": ErrorResponse, "description": "API key not found"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def get_api_key(
    key_id: str,
    service: ApiKeyService = Depends(get_api_key_service),
):
    return await service.get_key(key_id)


@router.delete(
    "/{key_id}",
    response_model=MessageResponse,
    responses={
        404: {"model": ErrorResponse, "description": "API key not found"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def revoke_api_key(
    key_id: str,
    service: ApiKeyService = Depends(get_api_key_service),
):
    return await service.revoke_key(key_id)
