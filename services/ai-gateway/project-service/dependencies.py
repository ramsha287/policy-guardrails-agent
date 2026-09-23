from typing import AsyncIterator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database.session import SessionLocal
from repositories.api_key_repository import ApiKeyRepository
from repositories.project_repository import ProjectRepository
from services.api_key_service import ApiKeyService
from services.project_service import ProjectService


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session


def get_project_service(session: AsyncSession = Depends(get_session)) -> ProjectService:
    return ProjectService(repository=ProjectRepository(session))


def get_api_key_service(session: AsyncSession = Depends(get_session)) -> ApiKeyService:
    return ApiKeyService(repository=ApiKeyRepository(session))
