import hashlib
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass
class ValidatedApiKey:
    id: str
    name: str


class ApiKeyValidator:
    """Validates an inbound API key against the shared `api_keys` table.

    The validation and usage-count increment happen in a single atomic UPDATE
    so a key cannot be counted as used unless it is also valid+active.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def validate_and_increment(self, raw_key: str) -> Optional[ValidatedApiKey]:
        if not raw_key:
            return None

        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        result = await self.session.execute(
            text(
                """
                UPDATE api_keys
                   SET usage_count = usage_count + 1,
                       last_used_at = NOW()
                 WHERE key_hash = :h
                   AND is_active = TRUE
                RETURNING id, name
                """
            ),
            {"h": key_hash},
        )
        row = result.first()
        await self.session.commit()
        if row is None:
            return None
        return ValidatedApiKey(id=str(row.id), name=row.name)
