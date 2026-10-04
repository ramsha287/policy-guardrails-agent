"""Everything the routers need, built once per process (tests build it with a MemoryStore)."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from ..services.admin import AdminKeyService
from ..services.analytics import AnalyticsService, Fetch
from ..services.assignments import AssignmentService
from ..services.catalog import CatalogService
from ..services.context import Ctx
from ..services.discovery import DiscoveryService
from ..services.gateways import GatewayService
from ..services.publishing import PublishService
from ..services.registry import RegistryService
from ..services.reviews import ReviewService
from ..services.simulation import SimulationService


@dataclass
class Container:
    ctx: Ctx
    internal_token: str
    http: httpx.AsyncClient
    gateway_url: str | None = None
    gateway_urls: dict[str, str] = field(default_factory=dict)
    analytics_fetch: Fetch | None = None  # runs SQL on the audit DSN; None = analytics disabled
    # Discovery: its own HTTP client (public trust store; connectors call cloud and SaaS APIs).
    discovery_http: httpx.AsyncClient | None = None
    discovery_allow_http: bool = False
    discovery_max_observations: int = 20_000

    def __post_init__(self) -> None:
        self.catalog = CatalogService(self.ctx)
        self.registry = RegistryService(self.ctx)
        self.assignments = AssignmentService(self.ctx)
        self.publishing = PublishService(self.ctx)
        self.reviews = ReviewService(self.ctx)
        self.gateways = GatewayService(self.ctx)
        self.admin_keys = AdminKeyService(self.ctx)
        self.analytics = AnalyticsService(self.analytics_fetch)
        self.discovery = DiscoveryService(
            self.ctx,
            self.discovery_http or self.http,
            audit_fetch=self.analytics_fetch,
            catalog=self.catalog,
            allow_http=self.discovery_allow_http,
            max_observations=self.discovery_max_observations,
        )
        self.simulation = SimulationService(
            self.ctx,
            self.registry,
            self.catalog,
            self.http,
            self.internal_token,
            gateway_urls=self.gateway_urls,
            default_gateway_url=self.gateway_url,
        )
