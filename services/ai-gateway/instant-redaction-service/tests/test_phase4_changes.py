"""Change 8 (per-scope rate limits) and change 9 (HMAC hashing per project)."""

import hashlib
import hmac

from tests.conftest import H1, H2

BASE = "/ai-gateway/redact/api"
EMAIL = "jane.doe@example.com"


async def _hash_of(client, project):
    r = await client.post(f"{BASE}/text", json={"text": EMAIL, "project_id": project})
    assert r.status_code == 200, r.text
    return r.json()["redacted_text"]


async def test_hash_is_hmac_per_project(client, monkeypatch):
    monkeypatch.setenv("HASH_SECRET", "s3cret-for-tests")
    h1, h2 = await _hash_of(client, H1), await _hash_of(client, H2)
    key = hmac.new(b"s3cret-for-tests", H1.encode(), hashlib.sha256).digest()
    assert h1 == hmac.new(key, EMAIL.encode(), hashlib.sha256).hexdigest()
    assert h1 != h2  # same value, different project -> different hash
    assert h1 != hashlib.sha256(EMAIL.encode()).hexdigest()  # not guessable without the secret


async def test_hash_without_secret_falls_back_to_presidio_hash(client, monkeypatch):
    monkeypatch.delenv("HASH_SECRET", raising=False)
    value = await _hash_of(client, H1)
    # Presidio's built-in sha256 operator (newer Presidio versions may salt it).
    assert len(value) == 64 and int(value, 16) >= 0


def test_rate_limiter_by_scope():
    from utils.rate_limit import RateLimiter

    rl = RateLimiter({"client": 2, "service": 0})
    assert rl.check("c", "client") is None and rl.check("c", "client") is None
    wait = rl.check("c", "client")
    assert wait is not None and 0 < wait <= 30
    assert all(rl.check("s", "service") is None for _ in range(100))  # 0 = unlimited
    assert rl.check("other", "client") is None  # buckets are per key
