"""Minimal local-LLM decision for the demo agent (session 8, path C).

Talks to a local Ollama server over HTTP (no API key, no cost, data stays on the machine).
Used ONLY for the demo / path-C scenario, never for the measured results (an LLM is not
deterministic). The agent used for all numbers stays the no-LLM rule-based one.
"""

import json
import os
import urllib.request

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
DEFAULT_MODEL = os.environ.get("MEMFW_LLM_MODEL", "llama3.1:8b")

SYSTEM = (
    "You are a refund-approval assistant for a shop. "
    "Your company policy and any customer notes are given to you as MEMORY. "
    "Approve a refund only if it complies with the policy. "
    "Answer with exactly one word, APPROVE or REJECT, and nothing else."
)


def chat(messages: list[dict], model: str = DEFAULT_MODEL, temperature: float = 0.0) -> str:
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature},
    }).encode("utf-8")
    req = urllib.request.Request(OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["message"]["content"].strip()


def decide_refund(amount: int, memory_lines: list[str], model: str = DEFAULT_MODEL,
                  temperature: float = 0.0) -> str:
    """Ask the LLM to decide a refund given the memory it can see. Returns 'approve' or 'reject'."""
    memory = "\n".join(f"- {line}" for line in memory_lines) or "- (no memory)"
    user = (
        f"MEMORY:\n{memory}\n\n"
        f"A customer requests a refund of ${amount}. "
        f"Following the policy in memory, do you APPROVE or REJECT?"
    )
    answer = chat([{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
                  model=model, temperature=temperature)
    upper = answer.upper()
    if "APPROVE" in upper and "REJECT" not in upper:
        return "approve"
    if "REJECT" in upper and "APPROVE" not in upper:
        return "reject"
    # Ambiguous: fall back to whichever word appears first.
    return "approve" if upper.find("APPROVE") <= upper.find("REJECT") else "reject"
