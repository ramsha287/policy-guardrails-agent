from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    environment: Literal["dev", "staging", "production"] = Field("dev", alias="GATEWAY_ENV")
    postgres_dsn: str = Field(..., alias="POSTGRES_DSN")
    log_level: str = Field("INFO", alias="LOG_LEVEL")

    # Policy engine (OPA sidecar)
    opa_url: str = Field("http://opa:8181", alias="OPA_URL")
    opa_decision_path: str = Field("/v1/data/guardrails/authz/decision", alias="OPA_DECISION_PATH")
    opa_timeout_ms: int = Field(300, alias="OPA_TIMEOUT_MS")

    # Guardrail engine
    snapshot_path: Path = Field(Path("/app/config/snapshots/dev.json"), alias="SNAPSHOT_PATH")
    snapshot_reload_seconds: int = Field(30, alias="SNAPSHOT_RELOAD_SECONDS")
    plugin_dirs: list[Path] = Field(default_factory=lambda: [APP_DIR / "plugins"], alias="PLUGIN_DIRS")
    default_guardrail_timeout_ms: int = Field(1000, alias="DEFAULT_GUARDRAIL_TIMEOUT_MS")
    http_timeout_seconds: float = Field(5.0, alias="HTTP_TIMEOUT_SECONDS")

    # Gateway limits
    max_body_bytes: int = Field(1_048_576, alias="MAX_BODY_BYTES")
    auth_cache_ttl_seconds: int = Field(30, alias="AUTH_CACHE_TTL_SECONDS")
    catalog_cache_ttl_seconds: int = Field(30, alias="CATALOG_CACHE_TTL_SECONDS")

    # Audit
    audit_queue_size: int = Field(10_000, alias="AUDIT_QUEUE_SIZE")
    audit_batch_size: int = Field(200, alias="AUDIT_BATCH_SIZE")
    audit_flush_seconds: float = Field(1.0, alias="AUDIT_FLUSH_SECONDS")
    audit_retention_months: int = Field(12, alias="AUDIT_RETENTION_MONTHS")

    # Optional
    redis_url: str | None = Field(None, alias="REDIS_URL")
    otel_endpoint: str | None = Field(None, alias="OTEL_EXPORTER_OTLP_ENDPOINT")
    bootstrap_env_file: Path | None = Field(None, alias="BOOTSTRAP_ENV_FILE")


def load_env_file(path: Path | None) -> None:
    """Load KEY=VALUE lines into os.environ without overriding existing values (dev bootstrap)."""
    if not path or not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
