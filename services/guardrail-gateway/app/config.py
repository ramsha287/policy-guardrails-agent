from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.risk.engine import RiskConfig

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

    # Where the snapshot and catalog come from:
    #   file          - SNAPSHOT_PATH + the gateway's own guardrail.* tables (phases 1-3)
    #   control_plane - published by guardrail-control-plane, cached on disk (phase 4+)
    config_source: Literal["file", "control_plane"] = Field("file", alias="CONFIG_SOURCE")
    control_plane_url: str | None = Field(None, alias="CONTROL_PLANE_URL")
    internal_token: str | None = Field(None, alias="INTERNAL_TOKEN")
    gateway_id: str | None = Field(None, alias="GATEWAY_ID")  # default: hostname
    cache_dir: Path = Field(Path("/var/cache/guardrail-gateway"), alias="CACHE_DIR")
    cp_poll_seconds: int = Field(30, alias="CP_POLL_SECONDS")
    heartbeat_seconds: int = Field(30, alias="HEARTBEAT_SECONDS")

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
    # Run audit partition maintenance (create next months, drop past retention) in this process.
    # Turn off when a CronJob runs `python -m app.cli partitions` instead (Helm does).
    audit_maintenance: bool = Field(True, alias="AUDIT_MAINTENANCE")
    # Disk spool for audit events the database can't take (outage, full queue); replayed later.
    # Empty string disables it (events are then dropped and counted instead).
    audit_spool_dir: str = Field("/var/cache/guardrail-gateway/audit-spool", alias="AUDIT_SPOOL_DIR")
    audit_spool_max_mb: int = Field(512, ge=1, alias="AUDIT_SPOOL_MAX_MB")

    # Per-API-key rate limit for /v1/guard and the proxy, per replica (0 = unlimited). A key's
    # rate_limit_per_minute in the control-plane catalog overrides it.
    guard_rate_limit_per_minute: int = Field(0, ge=0, alias="GUARD_RATE_LIMIT_PER_MINUTE")

    # Proxy mode: OpenAI-compatible /v1/chat/completions with the input/output/tool stages applied.
    proxy_enabled: bool = Field(False, alias="PROXY_ENABLED")
    proxy_upstream_url: str = Field("https://api.openai.com/v1", alias="PROXY_UPSTREAM_URL")
    proxy_upstream_api_key: str | None = Field(None, alias="PROXY_UPSTREAM_API_KEY")  # the provider key
    proxy_default_agent_id: str = Field("proxy", alias="PROXY_DEFAULT_AGENT_ID")
    proxy_models: list[str] = Field(default_factory=list, alias="PROXY_MODELS")  # empty = any model
    proxy_timeout_seconds: float = Field(120.0, gt=0, alias="PROXY_TIMEOUT_SECONDS")

    # Contextual decisions (app/risk/contextual.py)
    #   off: descriptors only · shadow: compute + audit, don't change decisions · enforce: apply the table
    risk_mode: Literal["off", "shadow", "enforce"] = Field("shadow", alias="RISK_MODE")
    # Reject API keys that aren't bound to one agent (identity assurance A0). Recommended in production
    # once every key has been bound in the console (Tenants & keys).
    require_bound_keys: bool = Field(False, alias="REQUIRE_BOUND_KEYS")
    # Domains treated as internal destinations (suffix match), e.g. "acme.com,acme.internal".
    internal_domains: str = Field("", alias="INTERNAL_DOMAINS")
    # JSON object overriding RiskConfig defaults (weights, caps, limits), e.g. {"elevated_row_limit": 500}.
    risk_config_json: str | None = Field(None, alias="RISK_CONFIG_JSON")
    # Session state without REDIS_URL is per replica; size of that in-memory store.
    session_memory_entries: int = Field(50_000, ge=100, alias="SESSION_MEMORY_ENTRIES")

    # Verification engine (app/verify): what a `verify` outcome can use instead of a human reviewer.
    # Off -> `verify` is held for review exactly like before.
    verification_enabled: bool = Field(True, alias="VERIFICATION_ENABLED")
    # User confirmation: tokens from your identity provider (OIDC). Needs issuer + audience + JWKS.
    verify_oidc_issuer: str | None = Field(None, alias="VERIFY_OIDC_ISSUER")
    verify_oidc_audience: str | None = Field(None, alias="VERIFY_OIDC_AUDIENCE")
    verify_oidc_jwks_url: str | None = Field(None, alias="VERIFY_OIDC_JWKS_URL")
    verify_oidc_jwks_json: str | None = Field(None, alias="VERIFY_OIDC_JWKS_JSON")
    verify_user_claim: str = Field("sub", alias="VERIFY_USER_CLAIM")
    verify_max_auth_age_seconds: int = Field(600, ge=30, alias="VERIFY_MAX_AUTH_AGE_SECONDS")
    verify_required_acr: str = Field("", alias="VERIFY_REQUIRED_ACR")  # comma-separated
    # The token's `nonce` must be the verification id (a sign-in started for this confirmation).
    # Off: any recent token of the user works, and the requesting agent's own key can't confirm.
    verify_require_nonce: bool = Field(True, alias="VERIFY_REQUIRE_NONCE")
    # Development only (refused unless GATEWAY_ENV=dev): accept HS256 tokens from `app.cli dev-user-token`.
    verify_dev_secret: str | None = Field(None, alias="VERIFY_DEV_SECRET")
    # SQL dry run: JSON {"<tool name or resource>": "<read-replica DSN>"}. Never the primary.
    verify_sql_dry_run: str | None = Field(None, alias="VERIFY_SQL_DRY_RUN")
    verify_dry_run_max_rows: int = Field(10_000, ge=1, alias="VERIFY_DRY_RUN_MAX_ROWS")

    # Advisors (app/advise): optional classifiers asked in the uncertain risk band; they can only add
    # capped risk points or ask for verification. JSON list of advisors, or
    # {"advisors": [...], "total_cap": 20, "bands": ["elevated", "high"]}. Empty = no advisors.
    # Example: [{"name": "local", "provider": "local", "mode": "shadow"}]
    advisors_json: str | None = Field(None, alias="ADVISORS_JSON")

    # Event outbox (app/events): decision events written with the audit rows, then published.
    # Comma-separated: "redis", "webhook" or both. Empty = no outbox rows are written at all.
    outbox_sinks: str = Field("", alias="OUTBOX_SINKS")
    outbox_webhook_url: str | None = Field(None, alias="OUTBOX_WEBHOOK_URL")
    outbox_webhook_secret: str | None = Field(None, alias="OUTBOX_WEBHOOK_SECRET")
    outbox_retention_days: int = Field(7, ge=1, alias="OUTBOX_RETENTION_DAYS")
    outbox_chain_heads_seconds: int = Field(3600, ge=60, alias="OUTBOX_CHAIN_HEADS_SECONDS")

    # Optional
    redis_url: str | None = Field(None, alias="REDIS_URL")
    otel_endpoint: str | None = Field(None, alias="OTEL_EXPORTER_OTLP_ENDPOINT")
    bootstrap_env_file: Path | None = Field(None, alias="BOOTSTRAP_ENV_FILE")


def risk_config(settings: Settings) -> RiskConfig:
    """RiskConfig defaults, overridden by RISK_CONFIG_JSON, plus INTERNAL_DOMAINS."""
    overrides = json.loads(settings.risk_config_json) if settings.risk_config_json else {}
    if not isinstance(overrides, dict):
        raise ValueError("RISK_CONFIG_JSON must be a JSON object")
    domains = [d.strip() for d in settings.internal_domains.split(",") if d.strip()]
    if domains:
        overrides["internal_domains"] = domains
    return RiskConfig.model_validate(overrides)


def check_verification_settings(settings: Settings) -> None:
    """Refuse development-only settings in production (fail at startup, not at the first request)."""
    if settings.environment != "dev" and settings.verify_dev_secret:
        raise RuntimeError(
            f"VERIFY_DEV_SECRET is for GATEWAY_ENV=dev only (this is {settings.environment}); configure VERIFY_OIDC_*"
        )
    if settings.verify_dev_secret and len(settings.verify_dev_secret) < 32:
        raise RuntimeError("VERIFY_DEV_SECRET must be at least 32 characters (e.g. `openssl rand -hex 32`)")


def outbox_sinks(settings: Settings) -> list[str]:
    sinks = [x.strip() for x in settings.outbox_sinks.split(",") if x.strip()]
    unknown = set(sinks) - {"redis", "webhook"}
    if unknown:
        raise ValueError(f"OUTBOX_SINKS: unknown sink(s) {sorted(unknown)}; use redis and/or webhook")
    if "redis" in sinks and not settings.redis_url:
        raise ValueError("OUTBOX_SINKS=redis needs REDIS_URL")
    if "webhook" in sinks and not settings.outbox_webhook_url:
        raise ValueError("OUTBOX_SINKS=webhook needs OUTBOX_WEBHOOK_URL")
    if "webhook" in sinks and settings.environment == "production" and not settings.outbox_webhook_secret:
        raise ValueError("OUTBOX_WEBHOOK_SECRET is required in production (receivers must verify the signature)")
    return sinks


def dry_run_targets(settings: Settings) -> dict[str, str]:
    raw = json.loads(settings.verify_sql_dry_run) if settings.verify_sql_dry_run else {}
    if not isinstance(raw, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in raw.items()):
        raise ValueError('VERIFY_SQL_DRY_RUN must be a JSON object {"tool or resource": "postgresql://..."}')
    return raw


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
