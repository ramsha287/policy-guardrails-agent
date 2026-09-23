import hashlib
import logging
import secrets
from typing import List

from exceptions import ApiKeyNotFoundError
from mappers.api_key_mapper import (
    map_list_to_api_key_responses,
    map_to_api_key_response,
)
from models.api_key_model import ApiKey
from repositories.api_key_repository import ApiKeyRepository
from schemas.api_key_schema import (
    ApiKeyCreate,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
)
from schemas.project_schema import MessageResponse

logger = logging.getLogger(__name__)

_KEY_PREFIX = "gw_"
_PREFIX_LENGTH = 12


def _generate_raw_key() -> str:
    return _KEY_PREFIX + secrets.token_urlsafe(32)


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ApiKeyService:
    def __init__(self, repository: ApiKeyRepository):
        self.repo = repository

    async def create_key(self, data: ApiKeyCreate) -> ApiKeyCreatedResponse:
        raw_key = _generate_raw_key()
        record = ApiKey(
            name=data.name,
            key_hash=_hash_key(raw_key),
            prefix=raw_key[:_PREFIX_LENGTH],
        )
        record = await self.repo.insert(record)
        logger.info("API key created: id=%s name='%s'", record.id, record.name)
        return ApiKeyCreatedResponse(
            id=str(record.id),
            name=record.name,
            key=raw_key,
        )

    async def list_keys(self, include_disabled: bool = False) -> List[ApiKeyResponse]:
        keys = await self.repo.find_all(include_disabled=include_disabled)
        logger.info("Fetched %d API keys (include_disabled=%s)", len(keys), include_disabled)
        return map_list_to_api_key_responses(keys)

    async def get_key(self, key_id: str) -> ApiKeyResponse:
        key = await self.repo.find_by_id(key_id)
        if key is None:
            raise ApiKeyNotFoundError(key_id)
        return map_to_api_key_response(key)

    async def revoke_key(self, key_id: str) -> MessageResponse:
        key = await self.repo.find_by_id(key_id)
        if key is None:
            raise ApiKeyNotFoundError(key_id)
        await self.repo.disable(key)
        logger.info("API key revoked: id=%s", key_id)
        return MessageResponse(message="API key revoked successfully")
