"""PoisonedRAG-style injection against the vector DB, and the ASR metric (brief §7, §12 #4).

An attack succeeds for a target query if, after the attacker's crafted passages are inserted
into the corpus, at least one of THAT query's injected passages appears in the top-k retrieved
results. ASR = fraction of target queries where this happens. No LLM is involved (the measure
is purely retrieval, exactly as in PoisonedRAG's retrieval metric).
"""

from dataclasses import dataclass

from lab.vectordb import build_collection, retrieve_ids


def poison_docs(injected: dict) -> list[dict]:
    """Flatten the injected file into corpus documents with ids inj_<qid>_<j>."""
    docs = []
    for qid, item in injected.items():
        for j, text in enumerate(item["adv_texts"]):
            docs.append({"id": f"inj_{qid}_{j}", "title": "", "text": text})
    return docs


@dataclass
class AsrResult:
    asr: float
    hits: int
    total: int
    corpus_docs: int
    injected_docs: int


def measure_asr(client, injected: dict, corpus: list[dict], k: int, name: str,
                author_gate=None) -> AsrResult:
    """Build a poisoned collection (clean corpus + injected passages) and measure ASR.

    author_gate(doc) -> bool may drop documents at write time (used in session 5 to model
    Guard's authorized-writer gate). With no gate, every injected passage is admitted.
    """
    poison = poison_docs(injected)
    admitted_poison = [d for d in poison if author_gate is None or author_gate(d)]
    col = build_collection(client, name, corpus + admitted_poison, reset=True)

    hits = 0
    for qid, item in injected.items():
        top = retrieve_ids(col, item["question"], k)
        if any(t.startswith(f"inj_{qid}_") for t in top):
            hits += 1
    return AsrResult(hits / len(injected), hits, len(injected), len(corpus), len(admitted_poison))


def recall_at_k(col, sample: list[dict], k: int = 5) -> float:
    """Self-retrieval recall proxy for normal search quality (brief §12 #7): query each
    sampled clean doc by its title and check the doc itself is in the top-k."""
    found = 0
    for d in sample:
        query = d["text"][:160]  # a snippet of the passage itself
        if d["id"] in retrieve_ids(col, query, k):
            found += 1
    return found / len(sample) if sample else 0.0
