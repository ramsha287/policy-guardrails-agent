from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_dsn: str = Field(..., alias="POSTGRES_DSN")
    log_level: str = Field("INFO", alias="LOG_LEVEL")

@lru_cache
def get_settings() -> Settings:
    return Settings()
