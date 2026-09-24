"""PostgreSQL implementation of the Store protocol (schema `control`)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from guardrail_sdk.documents import Assignment as AssignmentDoc

from ..db import models as m
from ..domain.records import (
    ActionRecord,
    AdminKeyRecord,
    AgentRecord,
    ApiKeyRecord,
    AssignmentRecord,
    CatalogRecord,
    ChangeRecord,
    GatewayRecord,
    GuardrailVersionRecord,
    ModifierRecord,
    PublishRequestRecord,
    ReviewRecord,
    SnapshotRecord,
    TenantRecord,
)
from .base import Conflict


def _cols(model: type[m.Base], data: dict[str, Any]) -> dict[str, Any]:
    names = {c.key for c in model.__table__.columns}
    return {k: v for k, v in data.items() if k in names}


class PgStore:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sm = sessionmaker
        self._tx: ContextVar[AsyncSession | None] = ContextVar("cp_tx", default=None)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        if self._tx.get() is not None:  # nested: join the outer transaction
            yield
            return
        async with self._sm() as s:
            try:
                async with s.begin():
                    token = self._tx.set(s)
                    try:
                        yield
                    finally:
                        self._tx.reset(token)
            except IntegrityError as exc:
                raise Conflict(str(exc.orig)) from exc

    @asynccontextmanager
    async def _s(self) -> AsyncIterator[AsyncSession]:
        current = self._tx.get()
        if current is not None:
            yield current
            return
        async with self._sm() as s:
            try:
                async with s.begin():
                    yield s
            except IntegrityError as exc:
                raise Conflict(str(exc.orig)) from exc

    async def _merge(self, model: type[m.Base], data: dict[str, Any]) -> None:
        async with self._s() as s:
            await s.merge(model(**_cols(model, data)))

    # ---- tenants ----------------------------------------------------------------------------

    async def get_tenant(self, tenant_id):
        async with self._s() as s:
            row = await s.get(m.Tenant, tenant_id)
            return TenantRecord.model_validate(row) if row else None

    async def list_tenants(self):
        async with self._s() as s:
            rows = (await s.execute(select(m.Tenant).order_by(m.Tenant.id))).scalars()
            return [TenantRecord.model_validate(r) for r in rows]

    async def put_tenant(self, tenant):
        await self._merge(m.Tenant, tenant.model_dump())

    # ---- api keys ---------------------------------------------------------------------------

    async def add_api_key(self, key):
        async with self._s() as s:
            s.add(m.ApiKey(**_cols(m.ApiKey, key.model_dump())))
            await s.flush()

    async def get_api_key(self, key_id):
        async with self._s() as s:
            row = await s.get(m.ApiKey, key_id)
            return ApiKeyRecord.model_validate(row) if row else None

    async def list_api_keys(self, tenant_id=None):
        q = select(m.ApiKey).order_by(m.ApiKey.created_at)
        if tenant_id is not None:
            q = q.where(m.ApiKey.tenant_id == tenant_id)
        async with self._s() as s:
            return [ApiKeyRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def put_api_key(self, key):
        await self._merge(m.ApiKey, key.model_dump())

    # ---- agents / actions / modifiers -------------------------------------------------------

    async def put_agent(self, agent):
        await self._merge(m.Agent, agent.model_dump())

    async def get_agent(self, tenant_id, agent_id):
        async with self._s() as s:
            row = await s.get(m.Agent, (tenant_id, agent_id))
            return AgentRecord.model_validate(row) if row else None

    async def list_agents(self, tenant_id=None):
        q = select(m.Agent).order_by(m.Agent.tenant_id, m.Agent.agent_id)
        if tenant_id is not None:
            q = q.where(m.Agent.tenant_id == tenant_id)
        async with self._s() as s:
            return [AgentRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def delete_agent(self, tenant_id, agent_id):
        async with self._s() as s:
            res = await s.execute(delete(m.Agent).where(m.Agent.tenant_id == tenant_id, m.Agent.agent_id == agent_id))
            return res.rowcount > 0

    async def put_action(self, action):
        stmt = (
            insert(m.Action)
            .values(**_cols(m.Action, action.model_dump()))
            .on_conflict_do_update(constraint="uq_cp_action", set_={"base_risk_score": action.base_risk_score})
            .returning(m.Action.id)
        )
        async with self._s() as s:
            action_id = (await s.execute(stmt)).scalar_one()
        return action.model_copy(update={"id": action_id})

    async def list_actions(self, tenant_id=None):
        q = select(m.Action).order_by(m.Action.tenant_id, m.Action.action, m.Action.resource_pattern)
        if tenant_id is not None:
            q = q.where(m.Action.tenant_id == tenant_id)
        async with self._s() as s:
            return [ActionRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def delete_action(self, tenant_id, action_id):
        async with self._s() as s:
            res = await s.execute(delete(m.Action).where(m.Action.id == action_id, m.Action.tenant_id == tenant_id))
            return res.rowcount > 0

    async def put_modifier(self, modifier):
        stmt = (
            insert(m.Modifier)
            .values(**_cols(m.Modifier, modifier.model_dump()))
            .on_conflict_do_update(constraint="uq_cp_modifier", set_={"delta": modifier.delta})
            .returning(m.Modifier.id)
        )
        async with self._s() as s:
            modifier_id = (await s.execute(stmt)).scalar_one()
        return modifier.model_copy(update={"id": modifier_id})

    async def list_modifiers(self, tenant_id=None):
        q = select(m.Modifier).order_by(m.Modifier.tenant_id, m.Modifier.kind, m.Modifier.value)
        if tenant_id is not None:
            q = q.where(m.Modifier.tenant_id == tenant_id)
        async with self._s() as s:
            return [ModifierRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def delete_modifier(self, tenant_id, modifier_id):
        async with self._s() as s:
            res = await s.execute(
                delete(m.Modifier).where(m.Modifier.id == modifier_id, m.Modifier.tenant_id == tenant_id)
            )
            return res.rowcount > 0

    # ---- registry ---------------------------------------------------------------------------

    async def put_version(self, version):
        await self._merge(m.GuardrailVersion, version.model_dump())

    async def get_version(self, guardrail_id, version):
        async with self._s() as s:
            row = await s.get(m.GuardrailVersion, (guardrail_id, version))
            return GuardrailVersionRecord.model_validate(row) if row else None

    async def list_versions(self, guardrail_id=None):
        q = select(m.GuardrailVersion).order_by(m.GuardrailVersion.guardrail_id, m.GuardrailVersion.version)
        if guardrail_id is not None:
            q = q.where(m.GuardrailVersion.guardrail_id == guardrail_id)
        async with self._s() as s:
            return [GuardrailVersionRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    # ---- assignments ------------------------------------------------------------------------

    @staticmethod
    def _assignment_row(r: AssignmentRecord) -> m.Assignment:
        return m.Assignment(
            environment=r.environment,
            id=r.assignment.id,
            order=r.assignment.order,
            document=r.assignment.model_dump(mode="json"),
            updated_by=r.updated_by,
            updated_at=r.updated_at,
        )

    @staticmethod
    def _assignment_record(row: m.Assignment) -> AssignmentRecord:
        return AssignmentRecord(
            environment=row.environment,  # type: ignore[arg-type]
            assignment=AssignmentDoc.model_validate(row.document),
            updated_by=row.updated_by,
            updated_at=row.updated_at,
        )

    async def put_assignment(self, record):
        async with self._s() as s:
            await s.merge(self._assignment_row(record))

    async def get_assignment(self, environment, assignment_id):
        async with self._s() as s:
            row = await s.get(m.Assignment, (environment, assignment_id))
            return self._assignment_record(row) if row else None

    async def list_assignments(self, environment):
        q = (
            select(m.Assignment)
            .where(m.Assignment.environment == environment)
            .order_by(m.Assignment.order, m.Assignment.id)
        )
        async with self._s() as s:
            return [self._assignment_record(r) for r in (await s.execute(q)).scalars()]

    async def delete_assignment(self, environment, assignment_id):
        async with self._s() as s:
            res = await s.execute(
                delete(m.Assignment).where(m.Assignment.environment == environment, m.Assignment.id == assignment_id)
            )
            return res.rowcount > 0

    async def replace_assignments(self, environment, records):
        async with self._s() as s:
            await s.execute(delete(m.Assignment).where(m.Assignment.environment == environment))
            for r in records:
                s.add(self._assignment_row(r))
            await s.flush()

    # ---- snapshots --------------------------------------------------------------------------

    async def add_snapshot(self, snapshot):
        async with self._s() as s:
            s.add(m.Snapshot(**_cols(m.Snapshot, snapshot.model_dump())))
            await s.flush()

    async def get_snapshot(self, environment, version):
        q = select(m.Snapshot).where(m.Snapshot.environment == environment, m.Snapshot.version == version)
        async with self._s() as s:
            row = (await s.execute(q)).scalar_one_or_none()
            return SnapshotRecord.model_validate(row) if row else None

    async def current_snapshot(self, environment):
        q = (
            select(m.Snapshot)
            .join(m.EnvironmentState, m.EnvironmentState.current_snapshot_id == m.Snapshot.id)
            .where(m.EnvironmentState.environment == environment)
        )
        async with self._s() as s:
            row = (await s.execute(q)).scalar_one_or_none()
            return SnapshotRecord.model_validate(row) if row else None

    async def set_current_snapshot(self, environment, snapshot_id):
        stmt = (
            insert(m.EnvironmentState)
            .values(environment=environment, current_snapshot_id=snapshot_id)
            .on_conflict_do_update(index_elements=["environment"], set_={"current_snapshot_id": snapshot_id})
        )
        async with self._s() as s:
            await s.execute(stmt)

    async def list_snapshots(self, environment, limit=50):
        q = (
            select(m.Snapshot)
            .where(m.Snapshot.environment == environment)
            .order_by(m.Snapshot.published_at.desc())
            .limit(limit)
        )
        async with self._s() as s:
            return [SnapshotRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def count_snapshots(self, environment):
        async with self._s() as s:
            q = select(func.count()).select_from(m.Snapshot).where(m.Snapshot.environment == environment)
            return int((await s.execute(q)).scalar_one())

    # ---- catalog ----------------------------------------------------------------------------

    async def add_catalog(self, catalog):
        async with self._s() as s:
            s.add(m.Catalog(**_cols(m.Catalog, catalog.model_dump())))
            await s.flush()

    async def current_catalog(self):
        async with self._s() as s:
            row = (await s.execute(select(m.Catalog).order_by(m.Catalog.seq.desc()).limit(1))).scalar_one_or_none()
            return CatalogRecord.model_validate(row) if row else None

    # ---- publish requests -------------------------------------------------------------------

    async def add_publish_request(self, request):
        async with self._s() as s:
            s.add(m.PublishRequest(**_cols(m.PublishRequest, request.model_dump())))
            await s.flush()

    async def get_publish_request(self, request_id):
        async with self._s() as s:
            row = await s.get(m.PublishRequest, request_id)
            return PublishRequestRecord.model_validate(row) if row else None

    async def put_publish_request(self, request):
        await self._merge(m.PublishRequest, request.model_dump())

    async def list_publish_requests(self, environment=None, status=None):
        q = select(m.PublishRequest).order_by(m.PublishRequest.requested_at.desc()).limit(200)
        if environment is not None:
            q = q.where(m.PublishRequest.environment == environment)
        if status is not None:
            q = q.where(m.PublishRequest.status == status)
        async with self._s() as s:
            return [PublishRequestRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    # ---- reviews ----------------------------------------------------------------------------

    async def add_review(self, review):
        async with self._s() as s:
            s.add(m.Review(**_cols(m.Review, review.model_dump())))
            await s.flush()

    async def get_review(self, review_id):
        async with self._s() as s:
            row = await s.get(m.Review, review_id)
            return ReviewRecord.model_validate(row) if row else None

    async def put_review(self, review):
        await self._merge(m.Review, review.model_dump())

    async def decide_review(self, review_id, *, status, reviewer, decided_at, decision_note):
        # Conditional UPDATE: two reviewers deciding at once can't both win, and a decision is
        # never overwritten by a stale read-modify-write.
        async with self._s() as s:
            result = await s.execute(
                update(m.Review)
                .where(m.Review.id == review_id, m.Review.status == "pending", m.Review.expires_at > decided_at)
                .values(status=status, reviewer=reviewer, decided_at=decided_at, decision_note=decision_note)
                .returning(m.Review.id)
            )
            return result.first() is not None

    async def add_review_raw_viewer(self, review_id, actor):
        async with self._s() as s:
            await s.execute(
                update(m.Review)
                .where(m.Review.id == review_id)
                .values(raw_viewed_by=func.array_append(m.Review.raw_viewed_by, actor))
            )

    async def list_reviews(self, tenant_id=None, status=None, limit=100):
        q = select(m.Review).order_by(m.Review.created_at.desc()).limit(limit)
        if tenant_id is not None:
            q = q.where(m.Review.tenant_id == tenant_id)
        if status is not None:
            q = q.where(m.Review.status == status)
        async with self._s() as s:
            return [ReviewRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    # ---- admin keys -------------------------------------------------------------------------

    async def add_admin_key(self, key):
        async with self._s() as s:
            s.add(m.AdminKey(**_cols(m.AdminKey, key.model_dump())))
            await s.flush()

    async def find_admin_key(self, key_hash):
        async with self._s() as s:
            row = (await s.execute(select(m.AdminKey).where(m.AdminKey.key_hash == key_hash))).scalar_one_or_none()
            return AdminKeyRecord.model_validate(row) if row else None

    async def list_admin_keys(self):
        async with self._s() as s:
            rows = (await s.execute(select(m.AdminKey).order_by(m.AdminKey.created_at))).scalars()
            return [AdminKeyRecord.model_validate(r) for r in rows]

    async def put_admin_key(self, key):
        await self._merge(m.AdminKey, key.model_dump())

    # ---- gateways ---------------------------------------------------------------------------

    async def put_gateway(self, gateway):
        await self._merge(m.Gateway, gateway.model_dump())

    async def list_gateways(self, environment=None):
        q = select(m.Gateway).order_by(m.Gateway.gateway_id)
        if environment is not None:
            q = q.where(m.Gateway.environment == environment)
        async with self._s() as s:
            return [GatewayRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    # ---- change log -------------------------------------------------------------------------

    async def log_change(self, change):
        async with self._s() as s:
            s.add(m.Change(**_cols(m.Change, change.model_dump(exclude={"id"}))))

    async def list_changes(self, entity=None, entity_id=None, limit=100):
        q = select(m.Change).order_by(m.Change.id.desc()).limit(limit)
        if entity is not None:
            q = q.where(m.Change.entity == entity)
        if entity_id is not None:
            q = q.where(m.Change.entity_id == entity_id)
        async with self._s() as s:
            return [ChangeRecord.model_validate(r) for r in (await s.execute(q)).scalars()]
