"""Per-API-key token buckets (GUARD_RATE_LIMIT_PER_MINUTE and the catalog's per-key override)."""

from app.engine.remote import CatalogHolder
from app.gateway.ratelimit import RateLimiter, retry_after_header


def test_unlimited_by_default():
    lim = RateLimiter(0)
    assert all(lim.check("k", now=0.0) is None for _ in range(1000))


def test_bucket_allows_a_minute_of_burst_then_refills():
    lim = RateLimiter(60)  # one per second, burst of 60
    assert all(lim.check("k", now=0.0) is None for _ in range(60))
    wait = lim.check("k", now=0.0)
    assert wait is not None and 0.9 < wait <= 1.0
    assert lim.check("k", now=1.0) is None  # one token back after a second
    assert lim.check("other", now=1.0) is None  # keys are independent
    assert retry_after_header(0.2) == "1" and retry_after_header(2.1) == "3"


def test_per_key_override():
    lim = RateLimiter(1000)
    assert lim.check("slow", override=1, now=0.0) is None
    assert lim.check("slow", override=1, now=0.0) is not None
    assert all(lim.check("vip", override=0, now=0.0) is None for _ in range(5000))  # 0 = unlimited for this key


def test_catalog_override_reaches_the_principal():
    import hashlib

    holder = CatalogHolder("dev")
    h = hashlib.sha256(b"gk_x").hexdigest()
    assert holder.apply(
        {
            "version": "c1",
            "tenants": [
                {
                    "id": "t",
                    "name": "T",
                    "api_keys": [{"id": "k", "name": "n", "key_hash": h, "rate_limit_per_minute": 30}],
                }
            ],
        }
    )
    assert holder._keys[h].rate_limit_per_minute == 30


def test_eviction_forgets_only_idle_buckets_and_stays_bounded():
    lim = RateLimiter(1000, max_keys=10)
    for i in range(10):
        lim.check(f"idle{i}", now=0.0)
    for _ in range(1000):
        assert lim.check("busy", now=90.0) is None
    lim.check("new", now=90.01)  # 12 keys > 10: eviction drops the idle ones (unused for >= 60 s)
    assert "busy" in lim._buckets and not any(k.startswith("idle") for k in lim._buckets)
    assert lim.check("busy", now=90.01) is not None  # still limited: its bucket was kept
    for i in range(30):  # more simultaneously active keys than max_keys: least recent go first
        lim.check(f"flood{i}", now=100.0 + i / 1000)
    assert len(lim._buckets) <= 10
