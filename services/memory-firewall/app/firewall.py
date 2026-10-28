"""The integration boundary: the only module that imports the Memory Firewall library.

The library (`guard`, `scan`, `lab` packages from the memory-firewall repository) is used exactly as
published, through its public classes and functions, and is never modified:

    guard.keys.load_or_create_signer / load_verifier   Ed25519 signing keys (with rotation support)
    guard.vector_guard.VectorGuard                    authorized-writer gate + per-source trust
    guard.events.EventLog                             JSONL event log tagged MITRE ATLAS AML.T0080
    scan.scanner.scan_text / scan_documents           heuristic scan for instruction-like memory
    lab.tamper.ATTACKS (in a subprocess, app.selftest) the five checkpoint attacks against GuardedSaver

What this adapter adds is process plumbing only: a lock (VectorGuard is not thread-safe), bounded
in-memory lists (the library's lists grow without limit in a long-running process) and reading the
tail of the event log.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import threading
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import guard
from guard.events import MITRE_CONTEXT_POISONING, EventLog
from guard.keys import load_or_create_signer, load_verifier
from guard.vector_guard import ALL_SOURCES, VectorGuard
from scan.scanner import INJECTION_PATTERNS, scan_documents, scan_text

SERVICE_DIR = Path(__file__).resolve().parents[1]


class SelfTestError(RuntimeError):
    """The checkpoint self-test could not run (timeout, crash, unreadable output)."""


@dataclass(frozen=True)
class Verdict:
    id: str
    source: str
    writer: str
    admitted: bool
    quarantine_reason: str | None
    scan_findings: list[str]
    signature: str | None


def library_version() -> str:
    """Version from the memory-firewall pyproject.toml next to the `src/` the library is loaded from."""
    pyproject = Path(guard.__file__).resolve().parents[2] / "pyproject.toml"
    try:
        return str(tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"])
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return "unknown"


class MemoryFirewall:
    def __init__(self, data_dir: Path, trusted_sources: list[str], max_provenance: int = 50_000) -> None:
        unknown = sorted(set(trusted_sources) - set(ALL_SOURCES))
        if unknown:
            raise ValueError(f"unknown trusted source(s) {unknown}; the library knows {list(ALL_SOURCES)}")
        self.data_dir = data_dir
        self.key_dir = data_dir / "keys"
        self.events_path = data_dir / "events.jsonl"
        self.selftest_dir = data_dir / "selftest"
        signer = load_or_create_signer(self.key_dir)
        self.key_id = hashlib.sha256(signer.public_raw()).hexdigest()[:16]
        self.events = EventLog(self.events_path)
        self.guard = VectorGuard(
            signer=signer,
            verifier=load_verifier(self.key_dir),
            events=self.events,
            trusted_sources=tuple(trusted_sources),
        )
        self.max_provenance = max_provenance
        self.started = time.time()
        self.admitted = 0
        self.quarantined = 0
        self.flagged = 0
        self._lock = threading.Lock()
        self._selftest_lock = asyncio.Lock()
        self.last_selftest: dict[str, Any] | None = None

    # ---- status ---------------------------------------------------------------------------------

    def ready(self) -> bool:
        return self.key_dir.is_dir() and os.access(self.data_dir, os.W_OK)

    def status(self) -> dict[str, Any]:
        with self._lock:
            provenance = len(self.guard.provenance)
            coverage = self.guard.coverage()
        last = self.last_selftest
        return {
            "service": "memory-firewall",
            "library_version": library_version(),
            "key_id": self.key_id,
            "trusted_sources": list(self.guard.trusted_sources),
            "sources": list(ALL_SOURCES),
            "mitre_technique": MITRE_CONTEXT_POISONING,
            "injection_patterns": len(INJECTION_PATTERNS),
            "uptime_seconds": round(time.time() - self.started, 1),
            "counters": {
                "admitted": self.admitted,
                "quarantined": self.quarantined,
                "scan_flagged": self.flagged,
                "provenance_records": provenance,
                "provenance_coverage": round(coverage, 4),
            },
            "last_selftest": None
            if last is None
            else {k: last[k] for k in ("passed", "finished_at", "duration_ms", "guard_blocked", "attacks")},
        }

    # ---- vector memory: authorized-writer gate + per-source trust (+ optional scan) -------------

    def inspect(self, items: list[dict[str, Any]], scan: bool) -> list[Verdict]:
        out: list[Verdict] = []
        with self._lock:
            for it in items:
                admitted = self.guard.admit({"id": it["id"]}, it["source"], it["writer"], bool(it["authorized"]))
                reason = None if admitted else self.guard.quarantined[-1][1]
                record = self.guard.provenance.get(it["id"]) if admitted else None
                findings = scan_text(it.get("text") or "") if scan else []
                out.append(
                    Verdict(
                        id=it["id"],
                        source=it["source"],
                        writer=it["writer"],
                        admitted=admitted,
                        quarantine_reason=reason,
                        scan_findings=findings,
                        signature=record["sig"].hex() if record else None,
                    )
                )
                self.admitted += admitted
                self.quarantined += not admitted
                self.flagged += bool(findings)
            self._trim()
        return out

    def _trim(self) -> None:
        # The library appends to these for the life of the process; only the latest entry is read here.
        self.guard.quarantined.clear()
        self.events.events.clear()
        prov = self.guard.provenance
        if len(prov) > self.max_provenance:
            for key in list(prov)[: len(prov) - self.max_provenance]:
                del prov[key]

    def verify_provenance(self, doc_id: str) -> dict[str, Any]:
        with self._lock:
            record = self.guard.provenance.get(doc_id)
            verified = self.guard.verify_provenance(doc_id)
        if record is None:
            return {"id": doc_id, "known": False, "verified": False}
        return {
            "id": doc_id,
            "known": True,
            "verified": verified,
            "source": record["source"],
            "writer": record["writer"],
        }

    # ---- scan: heuristics for memory that was never signed --------------------------------------

    @staticmethod
    def scan(items: list[dict[str, Any]]) -> dict[str, list[str]]:
        return scan_documents(items)

    # ---- event log ------------------------------------------------------------------------------

    def recent_events(self, limit: int) -> list[dict[str, Any]]:
        """The newest `limit` events, newest first, read from the end of the JSONL file."""
        try:
            size = self.events_path.stat().st_size
        except FileNotFoundError:
            return []
        block, data = 64 * 1024, b""
        with self.events_path.open("rb") as f:
            pos = size
            while pos > 0 and data.count(b"\n") <= limit:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
        events: list[dict[str, Any]] = []
        for line in reversed(data.splitlines()):
            if len(events) >= limit:
                break
            try:
                obj = json.loads(line)
            except ValueError:
                continue  # a partial first line or a line being written
            if isinstance(obj, dict):
                events.append(obj)
        return events

    # ---- checkpoint self-test: the library's own path-A attacks against GuardedSaver -------------

    async def self_test(self, limit_seconds: float) -> dict[str, Any]:
        """Runs `app.selftest` in a subprocess: the lab code writes into a relative `lab_runs/` directory,
        so it gets its own working directory, and a hung run can be killed without touching the server."""
        async with self._selftest_lock:
            self.selftest_dir.mkdir(parents=True, exist_ok=True)
            env = {
                **os.environ,
                "PYTHONPATH": os.pathsep.join(filter(None, [str(SERVICE_DIR), os.environ.get("PYTHONPATH")])),
            }
            started = time.perf_counter()
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "app.selftest",
                cwd=self.selftest_dir,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), limit_seconds)
            except TimeoutError as exc:
                proc.kill()
                await proc.wait()
                raise SelfTestError(f"self-test did not finish within {limit_seconds:.0f} s") from exc
            if proc.returncode != 0:
                tail = stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["no output"]
                raise SelfTestError(f"self-test exited with code {proc.returncode}: {tail[0][:300]}")
            try:
                result = json.loads(stdout)
            except ValueError as exc:
                raise SelfTestError("self-test printed no result") from exc
            result["duration_ms"] = round((time.perf_counter() - started) * 1000, 1)
            self.last_selftest = result
            return result
