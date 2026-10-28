"""Hands-on walkthrough of the lab agent: remember, decide, restart, peek into the database.

Usage:
    uv run lab-try                      # condition "plain" (no protection)
    uv run lab-try --mode encrypted     # LangGraph built-in encryption
    uv run lab-try --limit 700 --amounts 650 800
"""

import argparse
import shutil
import sqlite3

from lab.agent import build_agent, refund_event, remember_event, thread_config
from lab.store import MODES, default_lab_root, lab_paths, make_saver


def peek_latest_checkpoint(db_path, thread_id: str) -> tuple[str, bytes]:
    with sqlite3.connect(db_path) as conn:
        return conn.execute(
            "SELECT type, checkpoint FROM checkpoints WHERE thread_id = ? "
            "ORDER BY checkpoint_id DESC LIMIT 1",
            (thread_id,),
        ).fetchone()


def printable(blob: bytes, n: int = 70) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in blob[:n])


def main() -> None:
    ap = argparse.ArgumentParser(description="Step-by-step walkthrough of the lab agent")
    ap.add_argument("--mode", choices=MODES, default="plain")
    ap.add_argument("--limit", type=int, default=500)
    ap.add_argument("--amounts", type=int, nargs="+", default=[400, 900])
    args = ap.parse_args()

    root = default_lab_root() / "try"
    if root.exists():
        shutil.rmtree(root)
    db, keys = lab_paths(root, args.mode)
    cfg = thread_config("customer-1")

    print(f"\n=== Condition: {args.mode} ===")
    print(f"Database: {db}")

    print(f"\n[1] Agent is told to REMEMBER: refund limit = ${args.limit:,}")
    saver = make_saver(args.mode, db, keys)
    agent = build_agent(saver)
    agent.invoke(remember_event("refund_limit", str(args.limit)), cfg)
    print(f"    Agent memory now: {agent.get_state(cfg).values['facts']}")

    print("\n[2] Customer requests a refund:")
    for amount in args.amounts:
        decision = agent.invoke(refund_event(amount), cfg)["decision"]
        mark = "APPROVED" if decision == "approve" else "REJECTED"
        print(f"    refund {'$' + format(amount, ','):>10} -> {mark}")
    saver.conn.close()

    print("\n[3] RESTART: program closed and reopened (new saver & agent, same database file)")
    saver2 = make_saver(args.mode, db, keys)
    agent2 = build_agent(saver2)
    state = agent2.get_state(cfg).values
    print(f"    Agent still remembers: {state['facts']}")
    print(f"    Action history       : {state['history']}")
    saver2.conn.close()

    print("\n[4] Peeking directly into the database (what an attacker sees):")
    typ, blob = peek_latest_checkpoint(db, "customer-1")
    print(f"    data type  : {typ}")
    print(f"    raw (start): {printable(blob)}")
    readable = b"refund_limit" in db.read_bytes()
    verdict = "YES - it can be read and edited" if readable else "NO - encrypted"
    print(f"    Is 'refund_limit' readable in the DB file? {verdict}")
    print("\nDone. Also try the other condition: uv run lab-try --mode encrypted\n")


if __name__ == "__main__":
    main()
