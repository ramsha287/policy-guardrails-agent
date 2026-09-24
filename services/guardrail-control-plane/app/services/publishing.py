"""Publishing snapshots: validation, two-person approval, rollback, history.

Rules
- Publishing compiles the environment's working set; invalid snapshots never get a version.
- In protected environments (default: production) a publish or rollback creates a *request*
  that a different admin key must approve. The request records the live version it was based
  on; if another publish lands first the request becomes `stale` and must be re-requested, so
  nobody approves a diff they did not see.
- Requests expire after `publish_request_ttl_hours`.
- Snapshots are immutable. A rollback publishes a *new* version whose content equals an older
  one, and resets the working set to it so the next publish does not undo the rollback.
- Publishing identical content is a no-op.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

from guardrail_sdk.documents import SnapshotDoc, content_hash

from ..domain.compiler import compile_snapshot, etag, snapshot_version
from ..domain.rbac import Permission, Principal
from ..domain.records import AssignmentRecord, PublishRequestRecord, SnapshotRecord, utcnow
from ..errors import NotFound, StateConflict, ValidationFailed
from ..events import SNAPSHOT_CHANNEL
from ..metrics import SNAPSHOTS_PUBLISHED
from .context import Ctx
from .registry import RegistryService


@dataclass
class PublishOutcome:
    status: Literal["published", "pending_approval", "unchanged"]
    snapshot: SnapshotRecord | None = None
    request: PublishRequestRecord | None = None
    warnings: list[str] = field(default_factory=list)


def _assignments_hash(doc: SnapshotDoc) -> str:
    return content_hash(doc, {"version", "published_at", "published_by", "approved_by"})


class PublishService:
    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx
        self.store = ctx.store
        self.registry = RegistryService(ctx)

    def requires_approval(self, environment: str) -> bool:
        return environment in self.ctx.policy.two_person_environments

    async def _compile(self, environment: str, doc_assignments, *, force: bool):
        return compile_snapshot(
            environment,
            doc_assignments,
            await self.registry.versions_by_key(),
            await self.store.list_gateways(environment),
            force=force,
            stale_after_seconds=self.ctx.policy.gateway_stale_seconds,
        )

    async def _is_unchanged(self, environment: str, doc: SnapshotDoc) -> SnapshotRecord | None:
        current = await self.store.current_snapshot(environment)
        if current is not None and _assignments_hash(SnapshotDoc.model_validate(current.document)) == _assignments_hash(
            doc
        ):
            return current
        return None

    async def _submit(
        self,
        p: Principal,
        environment: str,
        doc: SnapshotDoc,
        warnings: list[str],
        *,
        kind: Literal["publish", "rollback"],
        note: str,
        rolled_back_from: str | None = None,
    ) -> PublishOutcome:
        unchanged = await self._is_unchanged(environment, doc)
        if unchanged is not None:
            return PublishOutcome("unchanged", snapshot=unchanged, warnings=warnings)
        if self.requires_approval(environment):
            current = await self.store.current_snapshot(environment)
            req = PublishRequestRecord(
                environment=environment,  # type: ignore[arg-type]
                kind=kind,
                document=doc.model_dump(mode="json"),
                base_version=current.version if current else None,
                rolled_back_from=rolled_back_from,
                requested_by=p.actor,
                requested_by_key=p.key_id,
                note=note,
            )
            await self.store.add_publish_request(req)
            await self.ctx.log(
                "publish_request", req.id, f"request:{kind}", p.actor, after={"environment": environment}
            )
            return PublishOutcome("pending_approval", request=req, warnings=warnings)
        async with self.store.transaction():
            snap = await self._commit(
                environment, doc, published_by=p.actor, approved_by=None, kind=kind, rolled_back_from=rolled_back_from
            )
        await self._announce(snap)
        return PublishOutcome("published", snapshot=snap, warnings=warnings)

    async def publish(self, p: Principal, environment: str, *, note: str = "", force: bool = False) -> PublishOutcome:
        p.require(Permission.PUBLISH_REQUEST)
        working = [r.assignment for r in await self.store.list_assignments(environment)]
        result = await self._compile(environment, working, force=force)
        if not result.ok:
            raise ValidationFailed(f"{environment} snapshot is invalid", result.errors, result.warnings)
        assert result.document is not None
        return await self._submit(p, environment, result.document, result.warnings, kind="publish", note=note)

    async def rollback(self, p: Principal, environment: str, target_version: str, *, note: str = "") -> PublishOutcome:
        p.require(Permission.PUBLISH_REQUEST)
        target = await self.store.get_snapshot(environment, target_version)
        if target is None:
            raise NotFound(f"snapshot {target_version} not found in {environment}")
        old = SnapshotDoc.model_validate(target.document)
        # force: a version deprecated since then is still allowed to come back
        result = await self._compile(environment, old.assignments, force=True)
        if not result.ok:
            raise ValidationFailed(f"cannot roll back to {target_version}", result.errors, result.warnings)
        assert result.document is not None
        return await self._submit(
            p,
            environment,
            result.document,
            result.warnings,
            kind="rollback",
            note=note or f"rollback to {target_version}",
            rolled_back_from=target_version,
        )

    async def approve(self, p: Principal, request_id: str, *, note: str = "") -> SnapshotRecord:
        p.require(Permission.PUBLISH_APPROVE)
        req = await self._pending(request_id)  # records `expired` before raising
        if req.requested_by_key == p.key_id:
            raise StateConflict("two-person rule: the approver must be a different admin key than the requester")
        if not await self._base_matches(req):
            await self.store.put_publish_request(req.model_copy(update={"status": "stale"}))
            raise StateConflict(f"{req.environment} changed since this request; request the publish again")
        doc = SnapshotDoc.model_validate(req.document)
        result = await self._compile(req.environment, doc.assignments, force=req.kind == "rollback")
        if not result.ok:
            raise ValidationFailed("snapshot is no longer valid", result.errors, result.warnings)
        async with self.store.transaction():
            if not await self._base_matches(req):  # a concurrent publish won the race
                raise StateConflict(f"{req.environment} changed while approving; request the publish again")
            snap = await self._commit(
                req.environment,
                doc,
                published_by=req.requested_by,
                approved_by=p.actor,
                kind=req.kind,
                rolled_back_from=req.rolled_back_from,
            )
            await self.store.put_publish_request(
                req.model_copy(
                    update={
                        "status": "approved",
                        "decided_by": p.actor,
                        "decided_at": utcnow(),
                        "decision_note": note,
                        "published_version": snap.version,
                    }
                )
            )
            await self.ctx.log("publish_request", request_id, "approve", p.actor, after={"version": snap.version})
        await self._announce(snap)
        return snap

    async def _base_matches(self, req: PublishRequestRecord) -> bool:
        current = await self.store.current_snapshot(req.environment)
        return (current.version if current else None) == req.base_version

    async def reject(self, p: Principal, request_id: str, *, note: str = "") -> PublishRequestRecord:
        p.require(Permission.PUBLISH_APPROVE)
        req = await self._pending(request_id)
        req = req.model_copy(
            update={"status": "rejected", "decided_by": p.actor, "decided_at": utcnow(), "decision_note": note}
        )
        await self.store.put_publish_request(req)
        await self.ctx.log("publish_request", request_id, "reject", p.actor)
        return req

    async def _pending(self, request_id: str) -> PublishRequestRecord:
        req = await self.store.get_publish_request(request_id)
        if req is None:
            raise NotFound(f"publish request {request_id} not found")
        if req.status != "pending":
            raise StateConflict(f"publish request is {req.status}")
        if utcnow() - req.requested_at > timedelta(hours=self.ctx.policy.publish_request_ttl_hours):
            await self.store.put_publish_request(req.model_copy(update={"status": "expired"}))
            raise StateConflict("publish request expired; request again")
        return req

    async def _commit(
        self,
        environment: str,
        doc: SnapshotDoc,
        *,
        published_by: str,
        approved_by: str | None,
        kind: str,
        rolled_back_from: str | None,
    ) -> SnapshotRecord:
        now = utcnow()
        sequence = await self.store.count_snapshots(environment) + 1
        final = doc.model_copy(
            update={
                "version": snapshot_version(environment, doc, sequence),
                "published_at": now,
                "published_by": published_by,
                "approved_by": approved_by,
            }
        )
        record = SnapshotRecord(
            environment=environment,  # type: ignore[arg-type]
            version=final.version,
            document=final.model_dump(mode="json"),
            etag=etag(content_hash(final)),
            published_at=now,
            published_by=published_by,
            approved_by=approved_by,
            kind=kind,  # type: ignore[arg-type]
            rolled_back_from=rolled_back_from,
        )
        await self.store.add_snapshot(record)
        await self.store.set_current_snapshot(environment, record.id)
        if kind in ("rollback", "import"):
            await self.store.replace_assignments(
                environment,
                [
                    AssignmentRecord(environment=environment, assignment=a, updated_by=published_by)  # type: ignore[arg-type]
                    for a in final.assignments
                ],
            )
        await self.ctx.log(
            "snapshot",
            f"{environment}/{record.version}",
            kind,
            published_by,
            after={"approved_by": approved_by, "rolled_back_from": rolled_back_from},
        )
        return record

    async def _announce(self, record: SnapshotRecord) -> None:
        """Notify gateways after the commit so they never fetch before the row is visible."""
        SNAPSHOTS_PUBLISHED.labels(record.environment, record.kind).inc()
        await self.ctx.events.publish(SNAPSHOT_CHANNEL, {"environment": record.environment, "version": record.version})

    async def import_snapshot(self, p: Principal, doc: SnapshotDoc, *, force: bool = True) -> SnapshotRecord:
        """Bootstrap/migration only (CLI): publish a snapshot file without the approval step."""
        p.require(Permission.PUBLISH_APPROVE)
        result = await self._compile(doc.environment, doc.assignments, force=force)
        if not result.ok:
            raise ValidationFailed("imported snapshot is invalid", result.errors, result.warnings)
        assert result.document is not None
        unchanged = await self._is_unchanged(doc.environment, result.document)
        if unchanged is not None:
            return unchanged
        async with self.store.transaction():
            snap = await self._commit(
                doc.environment,
                result.document,
                published_by=p.actor,
                approved_by=p.actor,
                kind="import",
                rolled_back_from=None,
            )
        await self._announce(snap)
        return snap

    async def current_document(self, environment: str) -> tuple[dict[str, Any], str] | None:
        rec = await self.store.current_snapshot(environment)
        return (rec.document, rec.etag) if rec else None

    async def history(self, p: Principal, environment: str, limit: int = 50) -> list[SnapshotRecord]:
        p.require(Permission.READ, p.tenant_id)
        return await self.store.list_snapshots(environment, limit)

    async def requests(self, p: Principal, environment: str | None, status: str | None) -> list[PublishRequestRecord]:
        p.require(Permission.READ, p.tenant_id)
        return await self.store.list_publish_requests(environment, status)
