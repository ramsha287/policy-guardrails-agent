"""Per-API-key rate limits for /v1/guard and the proxy (token bucket, per gateway replica).

GUARD_RATE_LIMIT_PER_MINUTE sets the default for every key (0 = unlimited). A key's own
`rate_limit_per_minute` in the control-plane catalog overrides it (0 = unlimited for that key).
The bucket holds one minute of requests, so short bursts are fine. Limits are per replica: with N
gateway replicas behind a load balancer, a key gets up to N times the limit, so divide the value
you want by the replica count (the Helm chart does this for you).

Memory is bounded by `max_keys` buckets (50,000 by default). Buckets unused for 60 s are full
again and are forgotten first. Only if more than `max_keys` keys are active within one minute are
the least recently used forgotten early (they start again with a full bucket).
"""

from __future__ import annotations

import math
import threading
import time


class RateLimiter:
    def __init__(self, default_per_minute: int = 0, max_keys: int = 50_000) -> None:
        self.default = max(0, default_per_minute)
        self._buckets: dict[str, tuple[float, float]] = {}  # key id -> (tokens, last refill)
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def limit_for(self, override: int | None) -> int:
        return self.default if override is None else max(0, override)

    def check(self, key_id: str, override: int | None = None, now: float | None = None) -> float | None:
        """None when allowed; otherwise seconds until the next request would be allowed."""
        per_minute = self.limit_for(override)
        if per_minute <= 0:
            return None
        now = time.monotonic() if now is None else now
        rate = per_minute / 60.0
        with self._lock:
            tokens, last = self._buckets.get(key_id, (float(per_minute), now))
            tokens = min(float(per_minute), tokens + (now - last) * rate)
            if tokens >= 1.0:
                self._buckets[key_id] = (tokens - 1.0, now)
                allowed = True
            else:
                self._buckets[key_id] = (tokens, now)
                allowed = False
            if len(self._buckets) > self._max_keys:
                self._evict(now)
        return None if allowed else max(0.001, (1.0 - tokens) / rate)

    def _evict(self, now: float) -> None:
        # A bucket is full again 60 s after its last use whatever its rate (capacity = one
        # minute of tokens), so forgetting it then changes nothing for that key.
        self._buckets = {k: v for k, v in self._buckets.items() if now - v[1] < 60.0}
        if len(self._buckets) > self._max_keys:  # still too many active keys: drop the least recent
            keep = sorted(self._buckets.items(), key=lambda kv: kv[1][1], reverse=True)[: self._max_keys // 2]
            self._buckets = dict(keep)


def retry_after_header(seconds: float) -> str:
    return str(max(1, math.ceil(seconds)))
