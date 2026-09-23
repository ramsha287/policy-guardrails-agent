from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from exceptions import ValidationError


class ApiKeyCreate(BaseModel):
    name: str = Field(..., examples=["frontend-prod"])

    @field_validator("name")
    @classmethod
    def name_must_not_be_blank(cls, v: str) -> str:
        if v is None or not v.strip():
            raise ValidationError("name cannot be null, empty, or blank")
        if len(v) > 100:
            raise ValidationError("name must be 100 characters or fewer")
        return v.strip()


class ApiKeyCreatedResponse(BaseModel):
    """Returned only at creation time. Contains the plaintext key — store it on the client immediately."""

    id: str
    name: str
    key: str


class ApiKeyResponse(BaseModel):
    """Returned by list/get endpoints. Never includes the plaintext key."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    prefix: str
    usage_count: int
    last_used_at: Optional[datetime]
    is_active: bool
    created_at: datetime

    @field_validator("id", mode="before")
    @classmethod
    def stringify_id(cls, v):
        return str(v) if v is not None else v
