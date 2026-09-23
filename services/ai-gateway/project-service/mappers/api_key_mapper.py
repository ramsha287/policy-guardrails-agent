from typing import Iterable, List

from models.api_key_model import ApiKey
from schemas.api_key_schema import ApiKeyResponse


def map_to_api_key_response(key: ApiKey) -> ApiKeyResponse:
    return ApiKeyResponse.model_validate(key)


def map_list_to_api_key_responses(keys: Iterable[ApiKey]) -> List[ApiKeyResponse]:
    return [map_to_api_key_response(k) for k in keys]
