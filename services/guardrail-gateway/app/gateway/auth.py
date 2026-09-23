"""API-key authentication. Keys are stored as SHA-256 hashes, like the ai-gateway project-service."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Protocol

KEY_PREFIX = "gk_"
SCOPE_INVOKE = "guard:invoke"


@dataclass(frozen=True)
class Principal:
    key_id: str
    tenant_id: str
    key_name: str
    scopes: frozenset[str]


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


class ApiKeyStore(Protocol):
    async def lookup(self, key_hash: str) -> Principal | None: ...


class Authenticator:
    """Caches lookups for a short TTL so auth is not a DB round trip on every call.

    Revocations take effect within `ttl_seconds`. Misses are cached for a shorter time.
    """

    def __init__(self, store: ApiKeyStore, ttl_seconds: int = 30, negative_ttl_seconds: int = 5) -> None:
        self._store = store
        self._ttl = ttl_seconds
        self._neg_ttl = negative_ttl_seconds
        self._cache: dict[str, tuple[float, Principal | None]] = {}

    async def authenticate(self, raw_key: str | None, required_scope: str = SCOPE_INVOKE) -> Principal | None:
        if not raw_key or len(raw_key) > 256:
            return None
        h = hash_key(raw_key)
        now = time.monotonic()
        cached = self._cache.get(h)
        if cached and cached[0] > now:
            principal = cached[1]
        else:
            principal = await self._store.lookup(h)
            self._cache[h] = (now + (self._ttl if principal else self._neg_ttl), principal)
            if len(self._cache) > 10_000:
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
        if principal is None or required_scope not in principal.scopes:
            return None
        return principal
