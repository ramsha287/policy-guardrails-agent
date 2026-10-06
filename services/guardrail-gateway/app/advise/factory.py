"""Builds the advisor panel from ADVISORS_JSON (validated at startup: a bad config stops the gateway)."""

from __future__ import annotations

import json
from typing import Any

from app.advise.contract import Advisor
from app.advise.panel import AdvisorPanel, PanelConfig
from app.advise.providers.local import LocalAdvisor
from app.advise.providers.remote import BedrockAdvisor, HttpAdvisor


def parse_config(raw: str | dict[str, Any] | list[Any] | None) -> PanelConfig | None:
    """ADVISORS_JSON is either a list of advisors or {"advisors": [...], "total_cap": 20, "bands": [...]}."""
    if raw is None or raw == "":
        return None
    data = json.loads(raw) if isinstance(raw, str) else raw
    if isinstance(data, list):
        data = {"advisors": data}
    if not isinstance(data, dict):
        raise ValueError("ADVISORS_JSON must be a JSON list of advisors or an object with `advisors`")
    cfg = PanelConfig.model_validate(data)
    return cfg if cfg.advisors else None


def build_advisor(spec_name: str, provider: str, options: dict[str, Any], env: dict[str, str] | None = None) -> Advisor:
    if provider == "local":
        return LocalAdvisor.from_options(spec_name, options)
    if provider == "http":
        return HttpAdvisor.from_options(spec_name, options, env)
    if provider == "bedrock":
        return BedrockAdvisor.from_options(spec_name, options)
    raise ValueError(f"unknown advisor provider {provider!r}")


def build_panel(
    raw: str | dict[str, Any] | list[Any] | None,
    *,
    env: dict[str, str] | None = None,
    overrides: dict[str, Advisor] | None = None,
) -> AdvisorPanel | None:
    """None when no advisors are configured. `overrides` replaces providers by name (tests, harness)."""
    cfg = parse_config(raw)
    if cfg is None:
        return None
    advisors: dict[str, Advisor] = {}
    for spec in cfg.advisors:
        if overrides and spec.name in overrides:
            advisors[spec.name] = overrides[spec.name]
        else:
            advisors[spec.name] = build_advisor(spec.name, spec.provider, spec.options, env)
    return AdvisorPanel(cfg, advisors)
