"""Guardrail registry, working-set assignments, publishing (two-person), rollback, history."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, model_validator

from ...domain.rbac import Principal
from ...services.publishing import PublishOutcome
from ...services.registry import load_manifest_yaml
from ..container import Container
from ..deps import container, principal

router = APIRouter(tags=["pipeline"])


class VersionIn(BaseModel):
    """A guardrail manifest as JSON (`manifest`) or as the guardrail.yaml text (`manifest_yaml`)."""

    manifest: dict[str, Any] | None = None
    manifest_yaml: str | None = Field(None, max_length=200_000)
    conformance_report: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _one_manifest(self) -> VersionIn:
        if (self.manifest is None) == (self.manifest_yaml is None):
            raise ValueError("send exactly one of manifest or manifest_yaml")
        return self


class PublishIn(BaseModel):
    note: str = Field("", max_length=1000)
    force: bool = False  # downgrade "not installed on gateway" / "deprecated" to warnings


class RollbackIn(BaseModel):
    version: str
    note: str = Field("", max_length=1000)


class DecisionIn(BaseModel):
    note: str = Field("", max_length=1000)


def _outcome(o: PublishOutcome) -> dict[str, Any]:
    return {
        "status": o.status,
        "snapshot": _snapshot(o.snapshot) if o.snapshot else None,
        "request": o.request.model_dump(mode="json", exclude={"document"}) if o.request else None,
        "warnings": o.warnings,
    }


def _snapshot(s: Any, with_document: bool = False) -> dict[str, Any]:
    return s.model_dump(mode="json", exclude=None if with_document else {"document"})


# ---- registry ---------------------------------------------------------------------------------


@router.post("/guardrails/versions", status_code=201)
async def register_version(body: VersionIn, p: Principal = Depends(principal), c: Container = Depends(container)):
    raw = body.manifest if body.manifest is not None else load_manifest_yaml(body.manifest_yaml or "")
    rec = await c.registry.register(p, raw, conformance_report=body.conformance_report)
    return rec.model_dump(mode="json")


@router.get("/guardrails")
async def list_versions(
    guardrail_id: str | None = None, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return [v.model_dump(mode="json") for v in await c.registry.list(p, guardrail_id)]


@router.post("/guardrails/{guardrail_id}/versions/{version}/deprecate")
async def deprecate(
    guardrail_id: str, version: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return (await c.registry.deprecate(p, guardrail_id, version)).model_dump(mode="json")


# ---- assignments ------------------------------------------------------------------------------


@router.get("/environments/{environment}/assignments")
async def list_assignments(environment: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    return [r.model_dump(mode="json") for r in await c.assignments.list(p, environment)]


@router.put("/environments/{environment}/assignments/{assignment_id}")
async def put_assignment(
    environment: str,
    assignment_id: str,
    body: dict[str, Any],
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    if body.get("id", assignment_id) != assignment_id:
        raise HTTPException(status_code=422, detail="body id does not match the URL")
    return (await c.assignments.put(p, environment, {**body, "id": assignment_id})).model_dump(mode="json")


@router.patch("/environments/{environment}/assignments/{assignment_id}")
async def patch_assignment(
    environment: str,
    assignment_id: str,
    body: dict[str, Any],
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    return (await c.assignments.patch(p, environment, assignment_id, body)).model_dump(mode="json")


@router.delete("/environments/{environment}/assignments/{assignment_id}", status_code=204)
async def delete_assignment(
    environment: str, assignment_id: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    await c.assignments.delete(p, environment, assignment_id)
    return Response(status_code=204)


@router.get("/environments/{environment}/diff")
async def diff(environment: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    return await c.assignments.diff(p, environment)


# ---- publishing -------------------------------------------------------------------------------


@router.post("/environments/{environment}/publish")
async def publish(
    environment: str, body: PublishIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return _outcome(await c.publishing.publish(p, environment, note=body.note, force=body.force))


@router.post("/environments/{environment}/rollback")
async def rollback(
    environment: str, body: RollbackIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return _outcome(await c.publishing.rollback(p, environment, body.version, note=body.note))


@router.get("/environments/{environment}/snapshots")
async def history(
    environment: str,
    limit: int = Query(50, ge=1, le=500),
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    return [_snapshot(s) for s in await c.publishing.history(p, environment, limit)]


@router.get("/environments/{environment}/snapshots/current")
async def current(environment: str, p: Principal = Depends(principal), c: Container = Depends(container)):
    await c.publishing.history(p, environment, 1)  # permission check
    live = await c.ctx.store.current_snapshot(environment)
    if live is None:
        raise HTTPException(status_code=404, detail=f"nothing published in {environment} yet")
    return _snapshot(live, with_document=True)


@router.get("/environments/{environment}/snapshots/{version}")
async def get_snapshot(
    environment: str, version: str, p: Principal = Depends(principal), c: Container = Depends(container)
):
    await c.publishing.history(p, environment, 1)  # permission check
    snap = await c.ctx.store.get_snapshot(environment, version)
    if snap is None:
        raise HTTPException(status_code=404, detail=f"snapshot {version} not found")
    return _snapshot(snap, with_document=True)


@router.get("/publish-requests")
async def list_requests(
    environment: str | None = None,
    status: str | None = None,
    p: Principal = Depends(principal),
    c: Container = Depends(container),
):
    return [r.model_dump(mode="json") for r in await c.publishing.requests(p, environment, status)]


@router.post("/publish-requests/{request_id}/approve")
async def approve(
    request_id: str, body: DecisionIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return _snapshot(await c.publishing.approve(p, request_id, note=body.note))


@router.post("/publish-requests/{request_id}/reject")
async def reject(
    request_id: str, body: DecisionIn, p: Principal = Depends(principal), c: Container = Depends(container)
):
    return (await c.publishing.reject(p, request_id, note=body.note)).model_dump(mode="json", exclude={"document"})
