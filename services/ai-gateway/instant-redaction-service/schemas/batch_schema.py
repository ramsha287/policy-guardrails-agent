import uuid
from typing import Any, List, Optional

from pydantic import BaseModel, Field, field_validator

from exceptions import ValidationError
from schemas.text_schema import Finding

MAX_BATCH_ITEMS = 100


def _validate_project_id(v: str) -> str:
    if v is None or not str(v).strip():
        raise ValidationError("project_id cannot be null, empty, or blank")
    try:
        uuid.UUID(str(v))
    except (ValueError, TypeError):
        raise ValidationError("project_id must be a valid UUID")
    return v


class BatchItem(BaseModel):
    id: str = Field(..., min_length=1, max_length=128)
    text: str


class TextBatchRequest(BaseModel):
    project_id: str
    items: List[BatchItem]

    @field_validator("project_id")
    @classmethod
    def project_id_must_be_uuid(cls, v: str) -> str:
        return _validate_project_id(v)

    @field_validator("items")
    @classmethod
    def items_limits(cls, v: List[BatchItem]) -> List[BatchItem]:
        if not v:
            raise ValidationError("items must contain at least one item")
        if len(v) > MAX_BATCH_ITEMS:
            raise ValidationError(f"items must contain at most {MAX_BATCH_ITEMS} entries")
        if len({i.id for i in v}) != len(v):
            raise ValidationError("item ids must be unique")
        return v


class BatchResult(BaseModel):
    id: str
    redacted_text: str
    redacted: bool
    findings: List[Finding]


class TextBatchResponse(BaseModel):
    results: List[BatchResult]
    offsets_basis: str = "normalized_text"


class JsonFinding(Finding):
    path: str


class JsonRedactionRequest(BaseModel):
    project_id: str
    data: Any

    @field_validator("project_id")
    @classmethod
    def project_id_must_be_uuid(cls, v: str) -> str:
        return _validate_project_id(v)


class JsonRedactionResponse(BaseModel):
    data: Any
    redacted: bool
    findings: Optional[List[JsonFinding]] = None
    offsets_basis: Optional[str] = None
