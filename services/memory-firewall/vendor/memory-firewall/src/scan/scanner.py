"""Scan mini: heuristics that flag already-poisoned memory that was never signed (brief §8).

Scan runs BEFORE a client adopts Guard, on an existing store, so it cannot rely on
signatures - only on heuristics, measured by precision/recall (brief §12 #9, target only):

  H1  unsafe serialization in a checkpoint (pickle / CWE-502 class)
  H2  command-like / instruction-injection text in a memory ("ignore previous instructions")
  H3  near-duplicate clusters in a vector store (an entry with many near-identical siblings)

These are a first-pass net, not a guarantee. H1/H2 catch explicit signals well; H3 is weak
against paraphrase attacks (documented in the session-6 results).
"""

import re
import sqlite3
from pathlib import Path

SAFE_SERIALIZERS = ("msgpack", "json", "bytes", "null", "empty")

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(the\s+)?(previous|above|prior|earlier)\s+(instructions?|context|messages?|rules?)",
    r"disregard\s+(the\s+|all\s+)?(previous|above|prior|earlier|instructions?)",
    r"forget\s+(everything|all|previous|prior)",
    r"new\s+instructions?\s*:",
    r"(reveal|disclose|print|output|show)\s+(your\s+|the\s+)?(system\s+prompt|instructions?|secrets?|api[\s_-]?keys?|password)",
    r"you\s+(must|should|are\s+required\s+to)\s+(now\s+)?(approve|ignore|reveal|send|transfer|delete)",
    r"always\s+(approve|answer|say|respond)",
    r"act\s+as\s+(a\s+)?(system|admin|developer|root)",
]
_INJ = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


def is_unsafe_serialization(type_str: str, blob: bytes) -> bool:
    t = (type_str or "").lower()
    if "pickle" in t:
        return True
    if t not in SAFE_SERIALIZERS and blob[:1] == b"\x80":  # pickle protocol opcode
        return True
    return False


def scan_text(text: str) -> list[str]:
    return [f"injection-text: {m.pattern[:30]}" for m in _INJ if m.search(text or "")]


def _printable_runs(blob: bytes, min_len: int = 4) -> str:
    """Extract ASCII text embedded in a serialized blob, for heuristic text scanning."""
    out, run = [], []
    for b in blob:
        if 32 <= b < 127:
            run.append(chr(b))
        else:
            if len(run) >= min_len:
                out.append("".join(run))
            run = []
    if len(run) >= min_len:
        out.append("".join(run))
    return " ".join(out)


def scan_checkpoint_db(db_path: Path) -> dict[str, list[str]]:
    """Return {checkpoint_id: [reasons]} for every checkpoint flagged as suspicious."""
    flagged: dict[str, list[str]] = {}
    with sqlite3.connect(db_path) as conn:
        for cid, typ, blob in conn.execute("SELECT checkpoint_id, type, checkpoint FROM checkpoints"):
            blob = blob if isinstance(blob, (bytes, bytearray)) else bytes(blob or b"")
            reasons = []
            if is_unsafe_serialization(typ, blob):
                reasons.append(f"unsafe-serialization: {typ}")
            reasons += scan_text(_printable_runs(blob))
            if reasons:
                flagged[cid] = reasons
    return flagged


def scan_documents(docs: list[dict]) -> dict[str, list[str]]:
    """Text-only heuristic scan of memory documents [{id, text}] -> {id: [reasons]}."""
    flagged = {}
    for d in docs:
        reasons = scan_text(d.get("text", ""))
        if reasons:
            flagged[d["id"]] = reasons
    return flagged


def near_duplicate_ids(ids: list[str], embeddings, sim_threshold: float = 0.9,
                       min_dupes: int = 3, k: int = 7) -> set[str]:
    """H3: ids whose embedding has >= min_dupes neighbors at cosine sim >= sim_threshold."""
    import numpy as np
    from sklearn.neighbors import NearestNeighbors

    emb = np.asarray(embeddings, dtype=np.float32)
    emb = emb / (np.linalg.norm(emb, axis=1, keepdims=True) + 1e-9)
    k = min(k, len(ids))
    dist, _ = NearestNeighbors(n_neighbors=k, metric="cosine").fit(emb).kneighbors(emb)
    sim = 1 - dist
    counts = (sim[:, 1:] >= sim_threshold).sum(axis=1)
    return {ids[i] for i in range(len(ids)) if counts[i] >= min_dupes}


def precision_recall(flagged: set[str], poison: set[str], universe: set[str]) -> tuple[float, float]:
    flagged &= universe
    tp = len(flagged & poison)
    fp = len(flagged - poison)
    fn = len(poison - flagged)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall
