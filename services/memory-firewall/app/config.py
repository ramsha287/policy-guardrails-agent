from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    # Callers (the gateway's `memory-firewall` guardrail, the control plane) send it in X-API-Key.
    api_key: str | None = Field(None, alias="MEMORY_FIREWALL_API_KEY")  # required (checked at start)
    # Signing keys, the event log and the self-test's scratch databases. Keep it on a volume the
    # agents' memory stores can't write: the threat model assumes an attacker can write the memory
    # database but cannot read the signing key.
    data_dir: Path = Field(Path("/var/lib/memory-firewall"), alias="MEMORY_FIREWALL_DATA_DIR")
    # Passed to the library's VectorGuard(trusted_sources=...). Its default is system + user.
    trusted_sources: list[str] = Field(
        default_factory=lambda: ["system", "user"], alias="MEMORY_FIREWALL_TRUSTED_SOURCES"
    )
    max_items: int = Field(200, ge=1, le=5000, alias="MEMORY_FIREWALL_MAX_ITEMS")
    max_text_chars: int = Field(32_768, ge=1, alias="MEMORY_FIREWALL_MAX_TEXT_CHARS")
    # Admitted provenance records kept in memory for /v1/provenance (the library keeps them in a dict).
    max_provenance_records: int = Field(50_000, ge=100, alias="MEMORY_FIREWALL_MAX_PROVENANCE")
    selftest_timeout_seconds: float = Field(120.0, gt=0, alias="MEMORY_FIREWALL_SELFTEST_TIMEOUT_SECONDS")
    log_level: str = Field("INFO", alias="LOG_LEVEL")


@lru_cache
def get_settings() -> Settings:
    return Settings()
