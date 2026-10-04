"""PostgreSQL implementation of the Store protocol (schema `control`)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any

from sqlalchemy import Text, and_, cast, delete, func, or_, select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from guardrail_sdk.documents import Assignment as AssignmentDoc

from ..db import models as m
from ..domain.inventory import (
    ConnectorRecord,
    EdgeRecord,
    EntityRecord,
    FindingRecord,
    ObservationRecord,
    SyncRunRecord,
)
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
        self._held: ContextVar[frozenset[str]] = ContextVar("cp_tenant_locks", default=frozenset())

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
    async def tenant_lock(self, tenant_id: str) -> AsyncIterator[None]:
        # A session-level advisory lock on its own connection: held across the many short
        # transactions of a run, released even if the run fails (and by Postgres if we die).
        held = self._held.get()
        if tenant_id in held:
            yield
            return
        key = f"inventory:{tenant_id}"
        engine = self._sm.kw["bind"]
        async with engine.connect() as raw:
            # One pinned connection in autocommit: lock and unlock happen on the same session.
            conn = await raw.execution_options(isolation_level="AUTOCOMMIT")
            await conn.execute(select(func.pg_advisory_lock(func.hashtext(key))))
            token = self._held.set(held | {tenant_id})
            try:
                yield
            finally:
                self._held.reset(token)
                await conn.execute(select(func.pg_advisory_unlock(func.hashtext(key))))

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
            .order_by(m.Snapshot.published_at.desc(), m.Snapshot.version.desc())  # sequence breaks ties
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

    # ---- discovery and inventory --------------------------------------------------------------

    async def put_connector(self, connector):
        await self._merge(m.Connector, connector.model_dump())

    async def get_connector(self, connector_id):
        async with self._s() as s:
            row = await s.get(m.Connector, connector_id)
            return ConnectorRecord.model_validate(row) if row else None

    async def list_connectors(self, tenant_id=None):
        q = select(m.Connector).order_by(m.Connector.tenant_id, m.Connector.name, m.Connector.id)
        if tenant_id is not None:
            q = q.where(m.Connector.tenant_id == tenant_id)
        async with self._s() as s:
            return [ConnectorRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def delete_connector(self, connector_id):
        async with self._s() as s:
            result = await s.execute(
                delete(m.Connector).where(m.Connector.id == connector_id).returning(m.Connector.id)
            )
            return result.first() is not None

    async def update_connector_fields(self, connector_id, fields):
        allowed = {c.key for c in m.Connector.__table__.columns} - {
            "id",
            "tenant_id",
            "kind",
            "lease_owner",
            "lease_until",
        }
        values = {k: v for k, v in fields.items() if k in allowed}
        if not values:
            return
        async with self._s() as s:
            await s.execute(update(m.Connector).where(m.Connector.id == connector_id).values(**values))

    async def claim_connector(self, connector_id, owner, now, lease_until, *, only_if_due=False):
        # Conditional UPDATE: of two replicas (or a scheduler tick and "sync now"), one wins.
        conditions = [
            m.Connector.id == connector_id,
            or_(m.Connector.lease_until.is_(None), m.Connector.lease_until <= now),
        ]
        if only_if_due:
            conditions += [
                m.Connector.enabled.is_(True),
                or_(
                    m.Connector.last_run_at.is_(None),
                    m.Connector.last_run_at + func.make_interval(0, 0, 0, 0, 0, m.Connector.interval_minutes) <= now,
                ),
            ]
        async with self._s() as s:
            result = await s.execute(
                update(m.Connector)
                .where(*conditions)
                .values(lease_owner=owner, lease_until=lease_until)
                .returning(m.Connector.id)
            )
            return result.first() is not None

    async def release_connector(self, connector_id, owner, *, status, error, finished_at):
        async with self._s() as s:
            await s.execute(
                update(m.Connector)
                .where(m.Connector.id == connector_id, m.Connector.lease_owner == owner)
                .values(
                    lease_owner=None, lease_until=None, last_run_at=finished_at, last_status=status, last_error=error
                )
            )

    async def put_run(self, run):
        await self._merge(m.SyncRun, run.model_dump())

    async def list_runs(self, connector_id, limit=20):
        q = (
            select(m.SyncRun)
            .where(m.SyncRun.connector_id == connector_id)
            .order_by(m.SyncRun.started_at.desc())
            .limit(limit)
        )
        async with self._s() as s:
            return [SyncRunRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def add_observations(self, observations):
        if not observations:
            return
        async with self._s() as s:
            await s.execute(
                insert(m.Observation).on_conflict_do_nothing(),
                [_cols(m.Observation, o.model_dump()) for o in observations],
            )

    async def list_observations(self, tenant_id, *, entity_id=None, run_id=None, limit=100):
        q = (
            select(m.Observation)
            .where(m.Observation.tenant_id == tenant_id)
            .order_by(m.Observation.observed_at.desc())
            .limit(limit)
        )
        if entity_id is not None:
            q = q.where(m.Observation.entity_id == entity_id)
        if run_id is not None:
            q = q.where(m.Observation.run_id == run_id)
        async with self._s() as s:
            return [ObservationRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def prune_observations(self, before):
        async with self._s() as s:
            result = await s.execute(delete(m.Observation).where(m.Observation.observed_at < before))
            return int(getattr(result, "rowcount", 0) or 0)

    async def put_entity(self, entity):
        await self._merge(m.Entity, entity.model_dump())

    async def get_entity(self, tenant_id, entity_id):
        async with self._s() as s:
            row = await s.get(m.Entity, entity_id)
            return EntityRecord.model_validate(row) if row is not None and row.tenant_id == tenant_id else None

    async def delete_entity(self, tenant_id, entity_id):
        async with self._s() as s:
            result = await s.execute(
                delete(m.Entity).where(m.Entity.id == entity_id, m.Entity.tenant_id == tenant_id).returning(m.Entity.id)
            )
            return result.first() is not None

    async def _overlap(self, tenant_id: str, column: Any, keys: list[str]) -> list[EntityRecord]:
        if not keys:
            return []
        wanted = cast(postgresql.array(list(keys)), postgresql.ARRAY(Text))
        q = select(m.Entity).where(m.Entity.tenant_id == tenant_id, column.op("&&")(wanted))
        async with self._s() as s:
            return [EntityRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def find_entities(self, tenant_id, keys):
        return await self._overlap(tenant_id, m.Entity.strong_keys, keys)

    async def find_entities_weak(self, tenant_id, keys):
        return await self._overlap(tenant_id, m.Entity.weak_keys, keys)

    async def list_entities(self, tenant_id, *, kind=None, state=None, agents_only=False, query=None, limit=500):
        q = (
            select(m.Entity)
            .where(m.Entity.tenant_id == tenant_id)
            .order_by(m.Entity.kind, m.Entity.name, m.Entity.id)
            .limit(limit)
        )
        if kind is not None:
            q = q.where(m.Entity.kind == kind)
        if state is not None:
            q = q.where(m.Entity.state == state)
        if agents_only:
            q = q.where(m.Entity.agent_likelihood != "none")
        if query:
            like = f"%{query.lower().replace('%', '').replace('_', '')}%"
            q = q.where(
                or_(
                    func.lower(m.Entity.name).like(like),
                    func.lower(func.array_to_string(m.Entity.strong_keys, " ")).like(like),
                )
            )
        async with self._s() as s:
            return [EntityRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def put_edge(self, edge):
        await self._merge(m.Edge, edge.model_dump())

    async def list_edges(self, tenant_id, *, entity_ids=None, source=None, open_only=True, as_of=None):
        q = select(m.Edge).where(m.Edge.tenant_id == tenant_id).order_by(m.Edge.valid_from, m.Edge.id)
        if entity_ids is not None:
            if not entity_ids:
                return []
            q = q.where(or_(m.Edge.src.in_(entity_ids), m.Edge.dst.in_(entity_ids)))
        if source is not None:
            q = q.where(m.Edge.source == source)
        if as_of is not None:
            q = q.where(m.Edge.valid_from <= as_of, or_(m.Edge.valid_to.is_(None), m.Edge.valid_to > as_of))
        elif open_only:
            q = q.where(m.Edge.valid_to.is_(None))
        async with self._s() as s:
            return [EdgeRecord.model_validate(r) for r in (await s.execute(q)).scalars()]

    async def put_finding(self, finding):
        await self._merge(m.Finding, finding.model_dump())

    async def get_finding(self, tenant_id, finding_id):
        async with self._s() as s:
            row = await s.get(m.Finding, finding_id)
            return FindingRecord.model_validate(row) if row is not None and row.tenant_id == tenant_id else None

    async def list_findings(self, tenant_id, *, status=None, entity_id=None, kind=None, limit=500):
        q = select(m.Finding).where(m.Finding.tenant_id == tenant_id).order_by(m.Finding.created_at.desc()).limit(limit)
        conds = [
            c
            for c in (
                m.Finding.status == status if status is not None else None,
                m.Finding.entity_id == entity_id if entity_id is not None else None,
                m.Finding.kind == kind if kind is not None else None,
            )
            if c is not None
        ]
        if conds:
            q = q.where(and_(*conds))
        async with self._s() as s:
            return [FindingRecord.model_validate(r) for r in (await s.execute(q)).scalars()]
