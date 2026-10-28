"""Checkpoint integrity self-test, run by the service in a subprocess (python -m app.selftest).

Calls the Memory Firewall library's own path-A attacks (`lab.tamper.ATTACKS`) for every storage
condition it ships (`lab.store.MODES`: plain, encrypted, guard). Each attack seeds a fresh SQLite
checkpoint database under ./lab_runs, manipulates it directly, and probes the lab agent's decision.
Prints one JSON object. Run it in a scratch directory: the library writes relative to the cwd.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from lab.store import MODES
from lab.tamper import ATTACKS, DETECTED, NA


def run() -> dict[str, object]:
    rows = []
    for attack in ATTACKS:
        for mode in MODES:
            o = attack(mode)
            rows.append(
                {"attack": o.attack, "mode": o.mode, "control": o.control, "tampered": o.tampered, "result": o.result}
            )
    guard = [r for r in rows if r["mode"] == "guard" and r["result"] != NA]
    blocked = sum(r["result"] == DETECTED for r in guard)
    return {
        "modes": list(MODES),
        "results": rows,
        "attacks": len(guard),
        "guard_blocked": blocked,
        "passed": blocked == len(guard) and len(guard) > 0,
        "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }


if __name__ == "__main__":
    print(json.dumps(run()))
