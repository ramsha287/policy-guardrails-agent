from io import BytesIO

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from auth.api_key_repository import ValidatedApiKey
from clients.project_client import ProjectClient, get_project_client
from config import get_settings
from dependencies import (
    get_redaction_service,
    require_api_key,
    validate_project_id_form,
)
from enums.file_type import FileType
from exceptions import ServiceUnavailableError
from schemas.error_schema import ErrorResponse
from schemas.text_schema import TextRedactionRequest, TextRedactionResponse
from services.redaction_service import RedactionService
from utils.file_utils import FileTypeDetector, FileValidator

router = APIRouter()

_MEDIA_TYPE_MAP = {
    FileType.IMAGE: "image/png",
    FileType.PDF: "application/pdf",
    FileType.TEXT: "text/plain",
    FileType.JSON: "application/json",
    FileType.CSV: "text/csv",
}


@router.get("/health")
async def health_check(
    project_client: ProjectClient = Depends(get_project_client),
):
    if not await project_client.is_healthy():
        raise ServiceUnavailableError("Project service unavailable")
    return {"status": "ok"}


@router.post(
    "/text",
    response_model=TextRedactionResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Validation error"},
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        404: {"model": ErrorResponse, "description": "Project not found"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def redact_text_endpoint(
    request: TextRedactionRequest,
    api_key: ValidatedApiKey = Depends(require_api_key),
    service: RedactionService = Depends(get_redaction_service),
):
    redacted_text = await service.redact_text(request.text, request.project_id)
    return TextRedactionResponse(redacted_text=redacted_text)


@router.post(
    "/file",
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        404: {"model": ErrorResponse, "description": "Project not found"},
        413: {"model": ErrorResponse, "description": "File too large"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def redact_file_pii(
    file: UploadFile = File(...),
    project_id: str = Depends(validate_project_id_form),
    api_key: ValidatedApiKey = Depends(require_api_key),
    service: RedactionService = Depends(get_redaction_service),
):
    settings = get_settings()
    max_bytes = settings.max_upload_size_mb * 1024 * 1024

    file_data = await file.read()
    if not file_data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(file_data) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {settings.max_upload_size_mb} MB",
        )

    file_bytes = BytesIO(file_data)
    file_type = FileTypeDetector.get_file_type(file.content_type)
    FileValidator.validate_file(file_bytes, file_type)

    result = await service.redact_file(file_bytes, file_type, project_id)

    return StreamingResponse(
        content=result,
        media_type=_MEDIA_TYPE_MAP[file_type],
        headers={"Content-Disposition": f"attachment; filename={file.filename}"},
    )
