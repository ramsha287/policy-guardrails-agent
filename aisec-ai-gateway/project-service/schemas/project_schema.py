import re
from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from exceptions import ValidationError
from utils.constants import ALLOWED_ENTITIES


class CustomizedItem(BaseModel):
    regex: str
    redaction: str

    @field_validator("regex")
    @classmethod
    def regex_must_be_valid_and_not_blank(cls, v: str) -> str:
        if v is None or not v.strip():
            raise ValidationError("regex cannot be null, empty, or blank")
        try:
            re.compile(v)
        except re.error:
            raise ValidationError("regex must be a valid regular expression")
        return v

    @field_validator("redaction")
    @classmethod
    def redaction_must_not_be_blank(cls, v: str) -> str:
        if v is None or not v.strip():
            raise ValidationError("redaction cannot be null, empty, or blank")
        return v


class ProjectCreate(BaseModel):
    project_name: str = Field(..., examples=["Project 1"])
    entities: Optional[List[str]] = Field(default_factory=list)
    customized: Optional[List[CustomizedItem]] = Field(default_factory=list)
    redaction_type: Literal["replace", "mask", "hash"] = Field(
        ..., examples=["replace"], description="Type of redaction to apply"
    )

    @field_validator("project_name")
    @classmethod
    def project_name_must_not_be_blank(cls, v: str) -> str:
        if v is None or not v.strip():
            raise ValidationError("project_name cannot be null, empty, or blank")
        return v

    @field_validator("entities", mode="before")
    @classmethod
    def no_duplicates_in_entities(cls, v):
        if v is None:
            return v
        if len(v) != len(set(v)):
            raise ValidationError("Entities list must not contain duplicates")
        return v

    @field_validator("entities")
    @classmethod
    def validate_entities(cls, v):
        invalid = [e for e in v if e not in ALLOWED_ENTITIES]
        if invalid:
            raise ValidationError(f"Invalid entities: {invalid}")
        return v

    @model_validator(mode="after")
    def no_duplicate_custom_regex(self):
        regexes = [item.regex for item in (self.customized or [])]
        if len(regexes) != len(set(regexes)):
            raise ValidationError("Regex patterns in customized must be unique")
        return self

    @model_validator(mode="after")
    def entities_or_customized_must_exist(self):
        if not (self.entities or []) and not (self.customized or []):
            raise ValidationError(
                "At least one of entities or customized must be provided and non-empty"
            )
        return self


class ProjectUpdate(BaseModel):
    project_name: Optional[str] = Field(None, examples=["Updated Project 1"])
    entities: Optional[List[str]] = Field(None, examples=[["PHONE_NUMBER", "EMAIL_ADDRESS"]])
    customized: Optional[List[CustomizedItem]] = None
    redaction_type: Optional[Literal["replace", "mask", "hash"]] = Field(
        None, examples=["replace"], description="Type of redaction to apply"
    )

    @field_validator("project_name")
    @classmethod
    def project_name_must_not_be_blank(cls, v):
        if v is not None and not v.strip():
            raise ValidationError("project_name cannot be empty or blank")
        return v

    @field_validator("entities", mode="before")
    @classmethod
    def no_duplicates_in_entities(cls, v):
        if v is None:
            return v
        if len(v) != len(set(v)):
            raise ValidationError("Entities list must not contain duplicates")
        return v

    @field_validator("entities")
    @classmethod
    def validate_entities(cls, v):
        if v is None:
            return v
        invalid = [e for e in v if e not in ALLOWED_ENTITIES]
        if invalid:
            raise ValidationError(f"Invalid entities: {invalid}")
        return v

    @model_validator(mode="after")
    def no_duplicate_custom_regex(self):
        if self.customized is not None:
            regexes = [item.regex for item in self.customized]
            if len(regexes) != len(set(regexes)):
                raise ValidationError("Regex patterns in customized must be unique")
        return self


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_name: str
    entities: Optional[List[str]] = Field(default_factory=list)
    customized: Optional[List[CustomizedItem]] = Field(default_factory=list)
    redaction_type: str
    created_at: datetime
    updated_at: datetime

    @field_validator("id", mode="before")
    @classmethod
    def stringify_id(cls, v):
        return str(v) if v is not None else v


class MessageResponse(BaseModel):
    message: str


class CreatedResponse(BaseModel):
    message: str
    project_id: str


class HealthResponse(BaseModel):
    status: str
