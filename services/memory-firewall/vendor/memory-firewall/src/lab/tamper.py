"""Path-A integrity tests: direct manipulations of the checkpoint database.

Defensive research only, run against our own isolated lab database (brief §4, §5). We do
NOT build exploits; we only check whether a storage-level manipulation changes what the
agent loads and decides. The attacker is assumed able to write to the DB file but NOT to
read the signing/encryption key (brief §5).

Each tamper function:
  1. seeds a fresh database with a known-good memory (refund limit),
  2. applies one manipulation by editing SQLite directly,
  3. reopens a fresh agent and probes a refund decision,
  4. reports an Outcome by comparing the probe to the untampered control.

Outcomes:
  SUCCEEDED  — the manipulation changed the agent's decision, with no error (undefended)
  DETECTED   — loading the tampered memory raised an error (the manipulation was caught)
  NO_EFFECT  — the manipulation did not change the decision
  N/A        — the manipulation does not apply to this condition
"""

import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from lab.agent import build_agent, refund_event, remember_event, thread_config
from lab.store import close_saver, lab_paths, make_saver

SUCCEEDED, DETECTED, NO_EFFECT, NA = "SUCCEEDED", "DETECTED", "NO_EFFECT", "N/A"
_plain = JsonPlusSerializer()


@dataclass
class Outcome:
    attack: str
    mode: str
    control: str   # agent decision on the untampered DB
    tampered: str  # agent decision after tampering (or "error")
    result: str    # one of SUCCEEDED / DETECTED / NO_EFFECT / N/A


def _fresh(mode: str, name: str) -> tuple[Path, Path]:
    root = Path("lab_runs") / "attacks" / name
    if root.exists():
        shutil.rmtree(root)
    return lab_paths(root, mode)


def _seed(mode, db, keys, thread, *limits):
    """Remember each limit in turn (last one wins); return nothing, just populate the DB."""
    saver = make_saver(mode, db, keys)
    agent = build_agent(saver)
    for lim in limits:
        agent.invoke(remember_event("refund_limit", str(lim)), thread_config(thread))
    close_saver(saver)


def _latest(conn, thread):
    return conn.execute(
        "SELECT checkpoint_id, type, checkpoint FROM checkpoints WHERE thread_id=? "
        "ORDER BY checkpoint_id DESC LIMIT 1",
        (thread,),
    ).fetchone()


def _edit_in_place(typ: str, blob: bytes, limit: int) -> tuple[str, bytes]:
    """Deserialize a genuine plaintext blob, change only the refund limit, reserialize.
    Keeps the real checkpoint id and versions, so the agent resumes normally."""
    obj = _plain.loads_typed((typ, blob))
    obj["channel_values"]["facts"] = {**obj["channel_values"].get("facts", {}),
                                      "refund_limit": str(limit)}
    return _plain.dumps_typed(obj)


def _genuine_plain_blob(limit: int) -> tuple[str, bytes]:
    """A real, internally consistent UNENCRYPTED checkpoint whose refund limit is `limit`,
    produced by a throwaway plain agent. The downgrade payload: valid structure, no key needed."""
    db, keys = _fresh("plain", f"_payload_{limit}")
    _seed("plain", db, keys, "x", limit)
    conn = sqlite3.connect(db)
    _, typ, blob = _latest(conn, "x")
    conn.close()
    return typ, blob


def _probe(mode, db, keys, thread, amount) -> str:
    """Open a fresh agent on the (possibly tampered) DB and return its refund decision,
    or 'error' if loading the memory failed."""
    saver = make_saver(mode, db, keys)
    agent = build_agent(saver)
    try:
        return agent.invoke(refund_event(amount), thread_config(thread))["decision"]
    except Exception:
        return "error"
    finally:
        close_saver(saver)


def _classify(control: str, tampered: str) -> str:
    if tampered == "error":
        return DETECTED
    return SUCCEEDED if tampered != control else NO_EFFECT


# --- the five path-A manipulations -------------------------------------------------

def edit_content(mode: str) -> Outcome:
    """Change the stored refund limit to a huge value.
    Encrypted mode: the attacker has no key, so they can only corrupt the ciphertext."""
    db, keys = _fresh(mode, f"edit_{mode}")
    _seed(mode, db, keys, "cust", 500)
    conn = sqlite3.connect(db)
    cid, typ, blob = _latest(conn, "cust")
    if mode == "encrypted":  # no key -> cannot forge valid ciphertext; corrupt one byte
        ntyp, nblob = typ, blob[:40] + bytes([blob[40] ^ 0xFF]) + blob[41:]
    else:  # plain / guard inner are plaintext: change the limit to a huge value
        ntyp, nblob = _edit_in_place(typ, blob, 1_000_000)
    conn.execute("UPDATE checkpoints SET type=?, checkpoint=? WHERE thread_id='cust' AND checkpoint_id=?",
                 (ntyp, nblob, cid))
    conn.commit(); conn.close()
    return Outcome("Edit content", mode, "reject", t := _probe(mode, db, keys, "cust", 900), _classify("reject", t))


def downgrade(mode: str) -> Outcome:
    """Swap in an attacker-chosen UNENCRYPTED, unsigned blob (no key needed).
    For encrypted mode this drops the encryption; for guard it is an unsigned blob."""
    if mode == "plain":
        return Outcome("Downgrade / unsigned blob", mode, "reject", "-", NA)
    db, keys = _fresh(mode, f"downgrade_{mode}")
    _seed(mode, db, keys, "cust", 500)
    conn = sqlite3.connect(db)
    cid, _, _ = _latest(conn, "cust")
    ntyp, nblob = _genuine_plain_blob(1_000_000)
    conn.execute("UPDATE checkpoints SET type=?, checkpoint=? WHERE thread_id='cust' AND checkpoint_id=?",
                 (ntyp, nblob, cid))
    conn.commit(); conn.close()
    return Outcome("Downgrade / unsigned blob", mode, "reject", t := _probe(mode, db, keys, "cust", 900), _classify("reject", t))


def replay(mode: str) -> Outcome:
    """Restore a previously valid, now-superseded memory over the current head (rollback)."""
    db, keys = _fresh(mode, f"replay_{mode}")
    _seed(mode, db, keys, "cust", 500)   # old, permissive policy
    conn = sqlite3.connect(db)
    _, old_typ, old_blob = _latest(conn, "cust")  # genuine blob with limit 500
    conn.close()
    _seed(mode, db, keys, "cust", 100)   # tightened policy (limit lowered to 100)
    conn = sqlite3.connect(db)
    cid, _, _ = _latest(conn, "cust")
    conn.execute("UPDATE checkpoints SET type=?, checkpoint=? WHERE thread_id='cust' AND checkpoint_id=?",
                 (old_typ, old_blob, cid))  # replay the old 500 blob as the head
    conn.commit(); conn.close()
    # Under the tightened policy (100) a $300 refund is rejected; replayed (500) it is approved.
    return Outcome("Replay old state", mode, "reject", t := _probe(mode, db, keys, "cust", 300), _classify("reject", t))


def truncation(mode: str) -> Outcome:
    """Delete the most recent checkpoint so the agent silently reverts to an older memory."""
    db, keys = _fresh(mode, f"truncate_{mode}")
    _seed(mode, db, keys, "cust", 500)   # permissive
    _seed(mode, db, keys, "cust", 100)   # tightened to 100
    conn = sqlite3.connect(db)
    # Remove the two newest checkpoints (the 'remember 100' step and its input).
    ids = [r[0] for r in conn.execute(
        "SELECT checkpoint_id FROM checkpoints WHERE thread_id='cust' ORDER BY checkpoint_id DESC LIMIT 2")]
    conn.executemany("DELETE FROM checkpoints WHERE thread_id='cust' AND checkpoint_id=?", [(i,) for i in ids])
    conn.commit(); conn.close()
    return Outcome("Truncate latest", mode, "reject", t := _probe(mode, db, keys, "cust", 300), _classify("reject", t))


def cross_thread(mode: str) -> Outcome:
    """Move thread A's genuine high-limit memory onto thread B."""
    db, keys = _fresh(mode, f"cross_{mode}")
    _seed(mode, db, keys, "vip", 1_000_000)  # thread 'vip': genuine high limit
    _seed(mode, db, keys, "cust", 500)        # thread 'cust': normal limit
    conn = sqlite3.connect(db)
    _, vip_typ, vip_blob = _latest(conn, "vip")
    cid, _, _ = _latest(conn, "cust")
    conn.execute("UPDATE checkpoints SET type=?, checkpoint=? WHERE thread_id='cust' AND checkpoint_id=?",
                 (vip_typ, vip_blob, cid))  # graft vip's blob onto cust
    conn.commit(); conn.close()
    return Outcome("Cross-thread move", mode, "reject", t := _probe(mode, db, keys, "cust", 900), _classify("reject", t))


ATTACKS = [edit_content, downgrade, replay, truncation, cross_thread]
