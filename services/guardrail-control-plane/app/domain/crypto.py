"""Encryption for payloads held in the review queue (they may contain sensitive data)."""

from __future__ import annotations

import json
import logging
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


class PayloadCipher:
    def __init__(self, key: str | None) -> None:
        if not key:
            logger.warning(
                "REVIEW_ENCRYPTION_KEY not set: using an ephemeral key. Held review payloads cannot be "
                "read after a restart. Set it in every non-dev deployment."
            )
            key = Fernet.generate_key().decode()
        self._fernet = Fernet(key.encode() if isinstance(key, str) else key)

    def encrypt(self, payload: dict[str, Any]) -> bytes:
        return self._fernet.encrypt(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    def decrypt(self, token: bytes) -> dict[str, Any] | None:
        try:
            return json.loads(self._fernet.decrypt(token).decode("utf-8"))
        except InvalidToken:
            logger.error("Could not decrypt a held review payload (key changed?)")
            return None
