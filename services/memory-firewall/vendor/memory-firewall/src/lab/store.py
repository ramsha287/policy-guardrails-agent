"""Checkpoint stores for the lab, one per comparison condition (brief §7).

    "plain"     — no protection (LangGraph default serializer)
    "encrypted" — LangGraph's built-in EncryptedSerializer (AES-EAX)
    "guard"     — our memory firewall (added in a later step)

Keys live in files outside the database (brief §5: the attacker can write to the DB but
cannot read the keys).
"""

import os
import secrets
import sqlite3
from pathlib import Path

from langgraph.checkpoint.serde.encrypted import EncryptedSerializer
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver

from guard.saver import make_guarded_saver

MODES = ("plain", "encrypted", "guard")


def load_or_create_key(path: Path, size: int = 32) -> bytes:
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(size)
    path.write_bytes(key)
    return key


def make_saver(mode: str, db_path: Path, key_dir: Path):
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}; expected one of {MODES}")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    if mode == "encrypted":
        key = load_or_create_key(key_dir / "aes.key")
        serde = EncryptedSerializer.from_pycryptodome_aes(key=key)
    else:  # "plain" and the inner saver of "guard" both use the plain serializer
        serde = JsonPlusSerializer()
    saver = SqliteSaver(conn, serde=serde)
    saver.setup()
    if mode != "guard":
        return saver
    # Guard: wrap the plain saver, keeping its ledger, keys and event log OUTSIDE the DB.
    guard_dir = db_path.parent.parent / "guard"
    return make_guarded_saver(
        db_path, saver,
        ledger_path=guard_dir / "ledger.sqlite",
        key_dir=guard_dir / "keys",
        events_path=guard_dir / "events.jsonl",
    )


def close_saver(saver) -> None:
    """Fully close a saver, including Guard's separate ledger/read connections.
    Accepts a GuardedSaver, a plain SqliteSaver, or either wrapped by TimingSaver."""
    if hasattr(saver, "ledger"):          # a GuardedSaver itself
        saver.close()
        return
    inner = getattr(saver, "inner", None)  # unwrap TimingSaver
    if inner is not None and hasattr(inner, "ledger"):
        inner.close()
        return
    (inner or saver).conn.close()


def lab_paths(root: Path, mode: str) -> tuple[Path, Path]:
    """Database and key directory for one condition, kept in separate folders."""
    return root / "db" / f"checkpoints_{mode}.sqlite", root / "keys" / mode


def default_lab_root() -> Path:
    return Path(os.environ.get("MEMFW_LAB_ROOT", Path.cwd() / "lab_runs"))
