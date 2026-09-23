"""Working-set assignments per environment. Nothing here reaches a gateway until published.

Tenant-scoped keys may manage assignments scoped to their own tenant (tenant or agent scope);
global assignments need a platform key.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from guardrail_sdk.documents import Assignment, SnapshotDoc

from ..domain.rbac import Permission, Principal
from ..domain.records import AssignmentRecord, utcnow
from ..errors import NotFound, ValidationFailed
from .context import Ctx

PATCHABLE = {
    "enabled",
    "mode",
    "order",
    "parallel_group",
    "failure_mode",
    "timeout_ms",
    "config",
    "stages",
    "guardrail_version",
}


def _check_env(environment: str) -> None:
    if environment not in ("dev", "staging", "production"):
        raise NotFound(f"unknown environment {environment}")


class AssignmentService:
    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx
        self.store = ctx.store

    async def list(self, p: Principal, environment: str) -> list[AssignmentRecord]:
        _check_env(environment)
        p.require(Permission.READ, p.tenant_id)
        return [
            r
            for r in await self.store.list_assignments(environment)
            if p.is_platform or r.assignment.tenant_id == p.tenant_id
        ]

    async def put(self, p: Principal, environment: str, raw: dict[str, Any]) -> AssignmentRecord:
        _check_env(environment)
        try:
            assignment = Assignment.model_validate(raw)
        except ValidationError as exc:
            raise ValidationFailed("invalid assignment", [e["msg"] for e in exc.errors()]) from exc
        p.require(Permission.ASSIGNMENTS_WRITE, assignment.tenant_id)
        if await self.store.get_version(assignment.guardrail_id, assignment.guardrail_version) is None:
            raise ValidationFailed(f"{assignment.guardrail_id}@{assignment.guardrail_version} is not registered")
        before = await self.store.get_assignment(environment, assignment.id)
        if before is not None:
            p.require(Permission.ASSIGNMENTS_WRITE, before.assignment.tenant_id)
        record = AssignmentRecord(environment=environment, assignment=assignment, updated_by=p.actor)  # type: ignore[arg-type]
        await self.store.put_assignment(record)
        await self.ctx.log(
            "assignment",
            f"{environment}/{assignment.id}",
            "update" if before else "create",
            p.actor,
            before=before.assignment.model_dump(mode="json") if before else None,
            after=assignment.model_dump(mode="json"),
        )
        return record

    async def patch(
        self, p: Principal, environment: str, assignment_id: str, changes: dict[str, Any]
    ) -> AssignmentRecord:
        """Partial update: enable/disable, reorder, switch shadow/enforce, change config or version."""
        _check_env(environment)
        unknown = set(changes) - PATCHABLE
        if unknown:
            raise ValidationFailed(f"cannot patch {sorted(unknown)}; allowed: {sorted(PATCHABLE)}")
        current = await self.store.get_assignment(environment, assignment_id)
        if current is None:
            raise NotFound(f"assignment {assignment_id} not found in {environment}")
        merged = {**current.assignment.model_dump(mode="json"), **changes}
        return await self.put(p, environment, merged)

    async def delete(self, p: Principal, environment: str, assignment_id: str) -> None:
        _check_env(environment)
        current = await self.store.get_assignment(environment, assignment_id)
        if current is None:
            raise NotFound(f"assignment {assignment_id} not found in {environment}")
        p.require(Permission.ASSIGNMENTS_WRITE, current.assignment.tenant_id)
        await self.store.delete_assignment(environment, assignment_id)
        await self.ctx.log(
            "assignment",
            f"{environment}/{assignment_id}",
            "delete",
            p.actor,
            before=current.assignment.model_dump(mode="json"),
        )

    async def diff(self, p: Principal, environment: str) -> dict[str, Any]:
        """What publishing now would change compared with the live snapshot."""
        _check_env(environment)
        p.require(Permission.READ, p.tenant_id)
        working = {
            r.assignment.id: r.assignment.model_dump(mode="json")
            for r in await self.store.list_assignments(environment)
        }
        current = await self.store.current_snapshot(environment)
        live: dict[str, Any] = {}
        if current is not None:
            live = {a.id: a.model_dump(mode="json") for a in SnapshotDoc.model_validate(current.document).assignments}
        return {
            "base_version": current.version if current else None,
            "added": sorted(set(working) - set(live)),
            "removed": sorted(set(live) - set(working)),
            "changed": sorted(k for k in set(working) & set(live) if working[k] != live[k]),
            "at": utcnow().isoformat(),
        }
