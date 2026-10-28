"""Guard for the vector DB: an authorized-writer gate + per-source provenance (brief §8, §5).

Signatures cannot vouch for the *meaning* of a vector-DB entry, so Guard adds two gates:

  1. Authorized-writer gate (path B): every write must carry a provenance record signed by an
     authorized writer. An attacker injecting directly into the store has no valid signature,
     so the write is refused and quarantined - it never reaches the index. -> ASR 0%.

  2. Per-source trust (path C, minimal): every admitted memory records its source
     (system / user / tool / web). Memory from an untrusted source (tool / web - the prompt-
     injection path) is quarantined rather than served. This does not solve "is the content
     true"; it records where each memory came from and holds untrusted sources back.

Honest limit (brief §5): this assumes the source label is correct. Knowing that a web
document is poisoned is the unsolved part; provenance only gives us the label to act on.
"""

from dataclasses import dataclass, field

from guard.events import EventLog
from guard.keys import Signer, Verifier

TRUSTED_SOURCES = ("system", "user")
ALL_SOURCES = ("system", "user", "tool", "web")


def _record(doc_id: str, source: str, writer: str) -> bytes:
    return f"{doc_id}|{source}|{writer}".encode("utf-8")


@dataclass
class VectorGuard:
    signer: Signer
    verifier: Verifier
    events: EventLog | None = None
    trusted_sources: tuple[str, ...] = TRUSTED_SOURCES
    require_authorized: bool = True
    provenance: dict[str, dict] = field(default_factory=dict)  # doc_id -> {source, writer, sig}
    quarantined: list[tuple[str, str]] = field(default_factory=list)  # (doc_id, reason)
    _handled: int = 0
    _with_source: int = 0

    def admit(self, doc: dict, source: str, writer: str, authorized: bool) -> bool:
        """Decide whether one write may enter the index. Records provenance for admits,
        quarantines (and logs) refusals. Returns True if admitted."""
        doc_id = doc["id"]
        self._handled += 1
        if source in ALL_SOURCES:
            self._with_source += 1
        if self.require_authorized and not authorized:
            return self._reject(doc_id, source, "unauthorized writer")
        if source not in self.trusted_sources:
            return self._reject(doc_id, source, f"untrusted source ({source}) quarantined")
        sig = self.signer.sign(_record(doc_id, source, writer))
        self.provenance[doc_id] = {"source": source, "writer": writer, "sig": sig}
        if self.events:
            self.events.write(writer, doc_id)
        return True

    def _reject(self, doc_id: str, source: str, reason: str) -> bool:
        self.quarantined.append((doc_id, reason))
        if self.events:
            self.events.reject(source, doc_id, reason)
        return False

    def verify_provenance(self, doc_id: str) -> bool:
        rec = self.provenance.get(doc_id)
        if rec is None:
            return False
        return self.verifier.verify(_record(doc_id, rec["source"], rec["writer"]), rec["sig"])

    def coverage(self) -> float:
        """Fraction of handled writes that carry a known source label (brief §12 #8)."""
        return 1.0 if self._handled == 0 else self._with_source / self._handled
