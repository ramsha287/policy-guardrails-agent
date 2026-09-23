import uuid
from typing import AsyncIterator, Optional

from fastapi import Depends, Form, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from auth.api_key_repository import ApiKeyValidator, ValidatedApiKey
from clients.project_client import ProjectClient, get_project_client
from database.session import SessionLocal
from exceptions import ValidationError
from services.redaction_service import RedactionService


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session


def get_redaction_service(
    project_client: ProjectClient = Depends(get_project_client),
) -> RedactionService:
    return RedactionService(project_service=project_client)


def validate_project_id_form(project_id: str = Form(...)) -> str:
    if not project_id or not project_id.strip():
        raise ValidationError("project_id cannot be null, empty, or blank")
    try:
        uuid.UUID(project_id)
    except (ValueError, TypeError):
        raise ValidationError("project_id must be a valid UUID")
    return project_id


async def require_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    session: AsyncSession = Depends(get_session),
) -> ValidatedApiKey:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    validator = ApiKeyValidator(session)
    validated = await validator.validate_and_increment(x_api_key)
    if validated is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    return validated
