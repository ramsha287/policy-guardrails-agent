"""Guard event log: one JSON object per line (JSONL), ready for the future Watch service.

Every write / load / reject / quarantine is recorded. Rejections carry a MITRE ATLAS tag
(AML.T0080 - AI Agent Context Poisoning) so a SIEM reads them in a language security teams
already use (brief §8 #5). Content is never logged - only identifiers and the reason.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

MITRE_CONTEXT_POISONING = "AML.T0080"

WRITE = "write"
LOAD = "load"
REJECT = "reject"
QUARANTINE = "quarantine"


@dataclass
class Event:
    event: str
    thread_id: str
    checkpoint_id: str | None = None
    checkpoint_ns: str = ""
    reason: str | None = None
    mitre: str | None = None
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds"))

    def to_json(self) -> str:
        return json.dumps({k: v for k, v in asdict(self).items() if v is not None}, sort_keys=True)


class EventLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.events: list[Event] = []

    def _emit(self, event: Event) -> None:
        self.events.append(event)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(event.to_json() + "\n")

    def write(self, thread_id, checkpoint_id, ns=""):
        self._emit(Event(WRITE, thread_id, checkpoint_id, ns))

    def load(self, thread_id, checkpoint_id, ns=""):
        self._emit(Event(LOAD, thread_id, checkpoint_id, ns))

    def reject(self, thread_id, checkpoint_id, reason, ns=""):
        self._emit(Event(REJECT, thread_id, checkpoint_id, ns, reason, MITRE_CONTEXT_POISONING))
        self._emit(Event(QUARANTINE, thread_id, checkpoint_id, ns, reason, MITRE_CONTEXT_POISONING))

    def count(self, event_type: str) -> int:
        return sum(1 for e in self.events if e.event == event_type)
