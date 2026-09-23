from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    postgres_dsn: str = Field(..., alias="POSTGRES_DSN")
    log_level: str = Field("INFO", alias="LOG_LEVEL")
    redis_url: str | None = Field(None, alias="REDIS_URL")

    # Shared secret for gateway -> control plane calls (/cp/v1/internal/*). mTLS in phase 5.
    internal_token: str | None = Field(None, alias="INTERNAL_TOKEN")  # required by the API (checked at start)
    # Fernet key for payloads held in the review queue.
    review_encryption_key: str | None = Field(None, alias="REVIEW_ENCRYPTION_KEY")

    # Policy
    two_person_environments: list[str] = Field(default_factory=lambda: ["production"], alias="TWO_PERSON_ENVIRONMENTS")
    publish_request_ttl_hours: int = Field(24, alias="PUBLISH_REQUEST_TTL_HOURS")
    review_ttl_minutes: int = Field(15, alias="REVIEW_TTL_MINUTES")
    gateway_stale_seconds: int = Field(300, alias="GATEWAY_STALE_SECONDS")

    # Gateway used for /simulate (it runs the real plugins)
    gateway_url: str | None = Field(None, alias="GATEWAY_URL")
    http_timeout_seconds: float = Field(10.0, alias="HTTP_TIMEOUT_SECONDS")

    # Optional read-only DSN for analytics over the gateway's audit schema
    audit_dsn: str | None = Field(None, alias="AUDIT_DSN")


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
