import uuid

from pydantic import BaseModel, field_validator

from exceptions import ValidationError


class TextRedactionRequest(BaseModel):
    text: str
    project_id: str

    @field_validator("text")
    @classmethod
    def text_must_not_be_blank(cls, v: str) -> str:
        if v is None or not str(v).strip():
            raise ValidationError("text cannot be null, empty, or blank")
        return v

    @field_validator("project_id")
    @classmethod
    def project_id_must_be_uuid(cls, v: str) -> str:
        if v is None or not str(v).strip():
            raise ValidationError("project_id cannot be null, empty, or blank")
        try:
            uuid.UUID(str(v))
        except (ValueError, TypeError):
            raise ValidationError("project_id must be a valid UUID")
        return v


class TextRedactionResponse(BaseModel):
    redacted_text: str
