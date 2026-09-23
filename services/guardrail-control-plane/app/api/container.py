"""Everything the routers need, built once per process (tests build it with a MemoryStore)."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from ..services.admin import AdminKeyService
from ..services.assignments import AssignmentService
from ..services.catalog import CatalogService
from ..services.context import Ctx
from ..services.gateways import GatewayService
from ..services.publishing import PublishService
from ..services.registry import RegistryService
from ..services.reviews import ReviewService


@dataclass
class Container:
    ctx: Ctx
    internal_token: str
    http: httpx.AsyncClient
    gateway_url: str | None = None
    audit_sessionmaker: object | None = None  # async_sessionmaker for analytics, optional

    def __post_init__(self) -> None:
        self.catalog = CatalogService(self.ctx)
        self.registry = RegistryService(self.ctx)
        self.assignments = AssignmentService(self.ctx)
        self.publishing = PublishService(self.ctx)
        self.reviews = ReviewService(self.ctx)
        self.gateways = GatewayService(self.ctx)
        self.admin_keys = AdminKeyService(self.ctx)
