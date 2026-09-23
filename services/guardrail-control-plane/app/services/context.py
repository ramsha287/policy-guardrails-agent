from __future__ import annotations

from dataclasses import dataclass, field

from ..domain.crypto import PayloadCipher
from ..domain.records import ChangeRecord
from ..events import EventPublisher
from ..store.base import Store


@dataclass
class Policy:
    """Operational rules (from settings)."""

    two_person_environments: frozenset[str] = frozenset({"production"})
    publish_request_ttl_hours: int = 24
    review_ttl_minutes: int = 15
    gateway_stale_seconds: int = 300


@dataclass
class Ctx:
    store: Store
    events: EventPublisher
    cipher: PayloadCipher
    policy: Policy = field(default_factory=Policy)

    async def log(self, entity: str, entity_id: str, action: str, actor: str, before=None, after=None) -> None:
        await self.store.log_change(
            ChangeRecord(entity=entity, entity_id=entity_id, action=action, actor=actor, before=before, after=after)
        )
