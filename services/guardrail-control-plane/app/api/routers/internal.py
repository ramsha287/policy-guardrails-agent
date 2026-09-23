"""Gateway -> control plane (X-Internal-Token). Snapshot/catalog fetch with ETags, heartbeat,
review queue. Gateways poll these; Redis events only make changes arrive sooner."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ...domain.records import Environment
from ..container import Container
from ..deps import container, internal

router = APIRouter(prefix="/internal", tags=["internal"], dependencies=[Depends(internal)])


class HeartbeatIn(BaseModel):
    gateway_id: str = Field(min_length=1, max_length=128)
    environment: Environment
    manifests: list[dict[str, Any]] = Field(default_factory=list)
    snapshot_version: str | None = None
    catalog_version: str | None = None
    last_error: str | None = Field(None, max_length=4000)


class ReviewIn(BaseModel):
    tenant_id: str
    environment: Environment
    request_id: str
    stage: str
    agent_id: str
    guardrail_id: str
    reason: str
    risk_score: int = Field(0, ge=0, le=100)
    payload: dict[str, Any]
    preview: str = ""


def _conditional(doc: dict[str, Any], etag: str, if_none_match: str | None) -> Response:
    if if_none_match and if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return JSONResponse(content=doc, headers={"ETag": etag, "Cache-Control": "no-cache"})


@router.get("/environments/{environment}/snapshot")
async def snapshot(
    environment: str,
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
    c: Container = Depends(container),
):
    current = await c.publishing.current_document(environment)
    if current is None:
        raise HTTPException(status_code=404, detail=f"nothing published in {environment} yet")
    return _conditional(current[0], current[1], if_none_match)


@router.get("/catalog")
async def catalog(
    if_none_match: str | None = Header(default=None, alias="If-None-Match"), c: Container = Depends(container)
):
    current = await c.catalog.current_document()
    if current is None:
        rec = await c.catalog.publish()  # empty catalog on a fresh install
        current = (rec.document, rec.etag)
    return _conditional(current[0], current[1], if_none_match)


@router.post("/gateways/heartbeat")
async def heartbeat(body: HeartbeatIn, c: Container = Depends(container)):
    g = await c.gateways.heartbeat(
        gateway_id=body.gateway_id,
        environment=body.environment,
        manifests=body.manifests,
        snapshot_version=body.snapshot_version,
        catalog_version=body.catalog_version,
        last_error=body.last_error,
    )
    return {"installed": g.installed, "last_error": g.last_error}


@router.post("/reviews", status_code=201)
async def create_review(body: ReviewIn, c: Container = Depends(container)):
    r = await c.reviews.create(**body.model_dump())
    return {"escalation_id": r.id, "expires_at": r.expires_at.isoformat()}


@router.get("/reviews/{review_id}")
async def review_status(review_id: str, tenant_id: str, c: Container = Depends(container)):
    return await c.reviews.status_for_gateway(review_id, tenant_id)
