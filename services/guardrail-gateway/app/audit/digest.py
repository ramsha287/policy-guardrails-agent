"""Payload digest for audit events (kept free of database imports)."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def payload_digest(payload: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON payload. The raw payload itself is never stored."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
