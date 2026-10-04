"""The connector kinds this control plane can run."""

from __future__ import annotations

from typing import Any

from .connectors.aws_bedrock import AwsBedrockConnector
from .connectors.dns_log import DnsLogConnector
from .connectors.gateway import GatewayConnector
from .connectors.kubernetes import KubernetesConnector
from .connectors.mcp import McpConnector
from .connectors.openai_admin import OpenAIAdminConnector
from .model import Connector

CONNECTORS: dict[str, Connector] = {
    c.kind: c
    for c in (
        GatewayConnector(),
        KubernetesConnector(),
        DnsLogConnector(),
        OpenAIAdminConnector(),
        AwsBedrockConnector(),
        McpConnector(),
    )
}


def get(kind: str) -> Connector | None:
    return CONNECTORS.get(kind)


def describe() -> list[dict[str, Any]]:
    return [
        {
            "kind": c.kind,
            "title": c.title,
            "description": c.description,
            "full_snapshot": c.full_snapshot,
            "config_schema": c.Config.model_json_schema(),
        }
        for c in CONNECTORS.values()
    ]
