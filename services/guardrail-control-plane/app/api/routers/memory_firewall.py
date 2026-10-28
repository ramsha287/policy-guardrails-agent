"""Memory Firewall (services/memory-firewall): status, event log, inspect, scan, checkpoint self-test."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from ...domain.rbac import Permission, Principal
from ...services.memory_firewall import MemoryFirewallService
from ...services.simulation import SimulationUnavailable
from ..container import Container
from ..deps import container, principal

router = APIRouter(prefix="/memory-firewall", tags=["memory-firewall"])


class InspectItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=300)
    text: str = Field("", max_length=32_768)
    source: str = Field(min_length=1, max_length=40)
    writer: str = Field(min_length=1, max_length=200)
    authorized: bool = True


class InspectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[InspectItem] = Field(min_length=1, max_length=50)
    scan: bool = True


class ScanItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=300)
    text: str = Field(max_length=32_768)


class ScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ScanItem] = Field(min_length=1, max_length=50)


def _service(c: Container) -> MemoryFirewallService:
    if c.memory_firewall is None:
        raise SimulationUnavailable("the Memory Firewall service is not configured (MEMORY_FIREWALL_URL)")
    return c.memory_firewall


@router.get("/status")
async def status(p: Principal = Depends(principal), c: Container = Depends(container)) -> dict[str, Any]:
    p.require(Permission.READ, p.tenant_id)
    if c.memory_firewall is None:
        return {"configured": False, "reachable": False, "ready": False}
    out = await c.memory_firewall.status()
    if not p.is_platform:
        out.pop("url", None)  # an internal address: platform keys only
    return out


@router.get("/events")
async def events(
    limit: int = Query(50, ge=1, le=500), p: Principal = Depends(principal), c: Container = Depends(container)
) -> dict[str, Any]:
    return await _service(c).events(p, limit)


@router.post("/scan")
async def scan(body: ScanIn, p: Principal = Depends(principal), c: Container = Depends(container)) -> dict[str, Any]:
    return await _service(c).scan(p, [i.model_dump() for i in body.items])


@router.post("/inspect")
async def inspect(
    body: InspectIn, p: Principal = Depends(principal), c: Container = Depends(container)
) -> dict[str, Any]:
    return await _service(c).inspect(p, [i.model_dump() for i in body.items], body.scan)


@router.post("/self-test")
async def self_test(p: Principal = Depends(principal), c: Container = Depends(container)) -> dict[str, Any]:
    return await _service(c).self_test(p)
