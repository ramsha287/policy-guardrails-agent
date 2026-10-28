"""Vector-DB lab (Chroma) with a pluggable public corpus (brief §7, path B).

Data (all gitignored, kept under data/):
  - Injected adversarial texts from the PoisonedRAG repo (MIT), one file for NQ:
    100 target questions, each with 5 crafted passages pushing a wrong answer.
  - A small sample of the clean BEIR/NQ corpus (distractor documents), streamed from
    HuggingFace so only a fraction is downloaded, then cached to a local JSONL.

The corpus loader is deliberately swappable: point CORPUS_SAMPLE at another JSONL (e.g.
synthetic company docs) and nothing else changes. Embeddings use Chroma's built-in local
MiniLM model (no API key, no GPU).
"""

import json
import os
import urllib.request
from pathlib import Path

INJECTED_URL = "https://raw.githubusercontent.com/sleeepeer/PoisonedRAG/main/results/adv_targeted_results/nq.json"


def data_dir() -> Path:
    d = Path(os.environ.get("MEMFW_DATA", "data"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_injected(dd: Path | None = None) -> dict:
    """{query_id: {question, correct answer, incorrect answer, adv_texts[5]}} for NQ."""
    dd = dd or data_dir()
    path = dd / "nq_injected.json"
    if not path.exists():
        urllib.request.urlretrieve(INJECTED_URL, path)
    return json.loads(path.read_text(encoding="utf-8"))


def load_corpus(n: int, dd: Path | None = None) -> list[dict]:
    """Return n clean distractor docs [{id,title,text}], cached locally after first stream."""
    dd = dd or data_dir()
    cache = dd / f"nq_corpus_{n}.jsonl"
    if cache.exists():
        return [json.loads(l) for l in cache.read_text(encoding="utf-8").splitlines()]

    from datasets import load_dataset

    ds = load_dataset("BeIR/nq", "corpus", split="corpus", streaming=True)
    docs, seen = [], set()
    for row in ds:
        if row["_id"] in seen or not row.get("text"):
            continue
        seen.add(row["_id"])
        docs.append({"id": row["_id"], "title": row.get("title", ""), "text": row["text"]})
        if len(docs) >= n:
            break
    with cache.open("w", encoding="utf-8") as f:
        for d in docs:
            f.write(json.dumps(d) + "\n")
    return docs


def doc_text(d: dict) -> str:
    return (d.get("title", "") + "\n" + d["text"]).strip()


def new_client(dd: Path | None = None):
    import chromadb

    dd = dd or data_dir()
    return chromadb.PersistentClient(path=str(dd / "chroma"))


def build_collection(client, name: str, docs: list[dict], reset: bool = False):
    """Create (or reuse) a Chroma collection embedding title+text with the default MiniLM."""
    existing = {c.name for c in client.list_collections()}
    if name in existing:
        if not reset:
            col = client.get_collection(name)
            if col.count() == len(docs):
                return col
        client.delete_collection(name)
    col = client.create_collection(name, metadata={"hnsw:space": "cosine"})
    ids = [d["id"] for d in docs]
    texts = [doc_text(d) for d in docs]
    for i in range(0, len(docs), 512):
        col.add(ids=ids[i:i + 512], documents=texts[i:i + 512])
    return col


def retrieve_ids(col, query: str, k: int = 5) -> list[str]:
    res = col.query(query_texts=[query], n_results=k)
    return res["ids"][0]
