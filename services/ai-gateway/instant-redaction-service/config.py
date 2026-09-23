from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    project_service_url: str = Field("http://project-service:8000", alias="PROJECT_SERVICE_URL")
    http_timeout_seconds: float = Field(10.0, alias="HTTP_TIMEOUT_SECONDS")
    max_upload_size_mb: int = Field(2, alias="MAX_UPLOAD_SIZE_MB")
    postgres_dsn: str = Field(..., alias="POSTGRES_DSN")
    log_level: str = Field("INFO", alias="LOG_LEVEL")
    # Project config cache (change 5). 0 disables caching.
    project_cache_ttl_seconds: float = Field(60.0, alias="PROJECT_CACHE_TTL_SECONDS")
    # Optional: project-service publishes project changes here so cached entries are evicted at once.
    redis_url: str | None = Field(None, alias="REDIS_URL")
    # Change 8: per-key rate limits by scope (requests per minute; 0 = unlimited).
    rate_limit_client_per_minute: int = Field(600, alias="RATE_LIMIT_CLIENT_PER_MINUTE")
    rate_limit_service_per_minute: int = Field(0, alias="RATE_LIMIT_SERVICE_PER_MINUTE")

@lru_cache
def get_settings() -> Settings:
    return Settings()
