"""Per-key token-bucket rate limits, configured per key scope (change 8).

`client` keys (apps calling the API directly) and `service` keys (the guardrail engine) get
separate budgets, so a noisy client cannot starve guardrail checks. Limits are per process;
with several replicas the effective limit is multiplied by the replica count.
"""
import threading
import time
from functools import lru_cache
from typing import Dict, Optional, Tuple

from config import get_settings


class RateLimiter:
    def __init__(self, per_minute_by_scope: Dict[str, int]):
        self._limits = per_minute_by_scope
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key id -> (tokens, last refill)
        self._lock = threading.Lock()

    def check(self, key_id: str, scope: str) -> Optional[float]:
        """None if allowed; otherwise seconds until a request would be allowed."""
        per_minute = self._limits.get(scope, self._limits.get("client", 0))
        if per_minute <= 0:
            return None
        rate = per_minute / 60.0
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key_id, (float(per_minute), now))
            tokens = min(float(per_minute), tokens + (now - last) * rate)
            if tokens >= 1.0:
                self._buckets[key_id] = (tokens - 1.0, now)
                return None
            self._buckets[key_id] = (tokens, now)
            return (1.0 - tokens) / rate


@lru_cache
def limiter() -> RateLimiter:
    s = get_settings()
    return RateLimiter({"client": s.rate_limit_client_per_minute, "service": s.rate_limit_service_per_minute})
