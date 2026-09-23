from __future__ import annotations

from pathlib import Path

import yaml
from cryptography.fernet import Fernet

from app.domain.crypto import PayloadCipher
from app.domain.rbac import Principal
from app.events import MemoryPublisher
from app.services.context import Ctx, Policy
from app.store.memory import MemoryStore

PLUGINS = Path(__file__).resolve().parents[2] / "guardrail-gateway" / "app" / "plugins"
PII_11 = yaml.safe_load((PLUGINS / "ai_gateway_pii" / "guardrail-1.1.0.yaml").read_text())
PII_10 = yaml.safe_load((PLUGINS / "ai_gateway_pii" / "guardrail.yaml").read_text())
NOOP = yaml.safe_load((PLUGINS / "noop" / "guardrail.yaml").read_text())
PROJECT = "3fa85f64-5717-4562-b3fc-2c963f66afa6"

ALICE = Principal("key-alice", "alice", frozenset({"admin"}))
BOB = Principal("key-bob", "bob", frozenset({"admin"}))
EDITOR = Principal("key-ed", "ed", frozenset({"editor"}))
VIEWER = Principal("key-vi", "vi", frozenset({"viewer"}))
ACME_ADMIN = Principal("key-acme", "acme-admin", frozenset({"admin"}), tenant_id="acme")
ACME_REVIEWER = Principal("key-acme-r", "acme-reviewer", frozenset({"reviewer"}), tenant_id="acme")
ACME_RAW = Principal("key-acme-raw", "acme-raw", frozenset({"reviewer-raw"}), tenant_id="acme")


def make_ctx(**policy) -> tuple[Ctx, MemoryStore, MemoryPublisher]:
    store, events = MemoryStore(), MemoryPublisher()
    ctx = Ctx(store=store, events=events, cipher=PayloadCipher(Fernet.generate_key().decode()), policy=Policy(**policy))
    return ctx, store, events


def pii_assignment(**over):
    base = {
        "id": "global-pii",
        "guardrail_id": "ai-gateway-pii",
        "guardrail_version": "1.1.0",
        "scope_type": "global",
        "stages": ["input", "output"],
        "order": 10,
        "mode": "enforce",
        "config": {"project_id": PROJECT},
    }
    base.update(over)
    return base
