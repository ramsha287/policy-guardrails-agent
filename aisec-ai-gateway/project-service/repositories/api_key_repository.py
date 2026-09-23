import uuid
from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.api_key_model import ApiKey


class ApiKeyRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    @staticmethod
    def _to_uuid(key_id: str) -> Optional[uuid.UUID]:
        try:
            return uuid.UUID(key_id)
        except (ValueError, TypeError):
            return None

    async def find_by_id(self, key_id: str) -> Optional[ApiKey]:
        kid = self._to_uuid(key_id)
        if kid is None:
            return None
        return await self.session.get(ApiKey, kid)

    async def find_all(self, include_disabled: bool = False) -> Sequence[ApiKey]:
        stmt = select(ApiKey).order_by(ApiKey.created_at.desc())
        if not include_disabled:
            stmt = stmt.where(ApiKey.is_active.is_(True))
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def insert(self, key: ApiKey) -> ApiKey:
        self.session.add(key)
        await self.session.commit()
        await self.session.refresh(key)
        return key

    async def disable(self, key: ApiKey) -> None:
        key.is_active = False
        await self.session.commit()
