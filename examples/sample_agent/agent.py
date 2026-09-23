"""A small, framework-free agent wired through all four guardrail stages.

The "LLM" is deterministic so tests can check exactly what it saw. Swap `fake_llm` for a real
model call; the hook calls stay the same.

    python examples/sample_agent/agent.py --url http://localhost:8100 --key gk_... \
        "Summarise the account for jane.doe@example.com"
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

from guardrail_sdk import Chunk, GuardClient, GuardHooks, GuardrailBlocked
from guardrail_sdk.integrations import guard_tool

KNOWLEDGE_BASE = [
    Chunk(id="kb-1", text="Refunds are processed within 5 business days.", source="policy.md"),
    Chunk(id="kb-2", text="Escalations go to the account owner, maria.lopez@example.com.", source="crm-notes"),
    Chunk(id="kb-3", text="Legacy record: customer SSN 536-90-4399 stored in the old system.", source="legacy"),
    Chunk(id="kb-4", text="Invoices are emailed on the first working day of the month.", source="billing.md"),
]
CUSTOMERS = {"[EMAIL_ADDRESS]": {"name": "Jane Doe", "phone": "+1 212 555 0199", "plan": "enterprise"}}
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+|\[[A-Z_]*EMAIL[A-Z_]*\]")


@dataclass
class Trace:
    """What each step saw. `llm_prompt` is exactly what the model received."""

    llm_prompt: str = ""
    retrieved: list[str] = field(default_factory=list)
    tool_calls: list[tuple[str, Any]] = field(default_factory=list)
    answer: str = ""
    blocked: str | None = None


def fake_llm(prompt: str) -> str:
    """Echoes its context so tests can see whether raw PII ever reached the model."""
    return f"Answer based on: {prompt}"


class SampleAgent:
    def __init__(self, hooks: GuardHooks) -> None:
        self.hooks = hooks

        @guard_tool(hooks, name="crm.lookup")
        async def crm_lookup(email: str) -> dict[str, Any]:
            # The tool only ever receives the (possibly redacted) argument.
            return {"email": email, **CUSTOMERS.get(email, {"name": "unknown"}), "owner": "maria.lopez@example.com"}

        @guard_tool(hooks, name="http.post")
        async def http_post(url: str, body: str) -> str:
            return f"posted {len(body)} bytes to {url}"

        self.crm_lookup = crm_lookup
        self.http_post = http_post

    def _search(self, query: str) -> list[Chunk]:
        words = {w for w in re.findall(r"[a-z]+", query.lower()) if len(w) > 3}
        return [c for c in KNOWLEDGE_BASE if words & set(re.findall(r"[a-z]+", c.text.lower()))] or KNOWLEDGE_BASE[:1]

    async def ask(self, question: str) -> Trace:
        trace = Trace()
        try:
            prompt = await self.hooks.before_llm(question)  # input stage

            chunks = await self.hooks.on_retrieval(self._search(prompt))  # retrieval stage
            trace.retrieved = [c.text for c in chunks]

            context = [f"Q: {prompt}", *[f"Doc: {c.text}" for c in chunks]]
            match = EMAIL_RE.search(prompt)
            if match:  # tool stage (before + after)
                record = await self.crm_lookup(email=match.group(0))
                trace.tool_calls.append(("crm.lookup", record))
                context.append(f"Customer: {record}")
            if "send" in prompt.lower():
                # Deliberately forwards the *original* question to an external tool: the tool-stage
                # guardrail must stop PII leaving the trust boundary even when the agent gets it wrong.
                sent = await self.http_post(url="https://partner.example.com/notes", body=question)
                trace.tool_calls.append(("http.post", sent))

            trace.llm_prompt = "\n".join(context)
            trace.answer = await self.hooks.after_llm(fake_llm(trace.llm_prompt))  # output stage
        except GuardrailBlocked as exc:
            trace.blocked = f"{exc.response.stage.value}: {exc.reason}"
            trace.answer = "Sorry, I can't help with that request."
        return trace


async def _main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("question")
    p.add_argument("--url", default=os.environ.get("GUARDRAIL_URL", "http://localhost:8100"))
    p.add_argument("--key", default=os.environ.get("GUARDRAIL_API_KEY"), required="GUARDRAIL_API_KEY" not in os.environ)
    p.add_argument("--agent", default="research-agent")
    p.add_argument("--classification", default="PII", choices=["PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII"])
    args = p.parse_args()
    async with GuardClient(args.url, args.key, agent_id=args.agent) as client:
        trace = await SampleAgent(GuardHooks(client, user_id="demo-user", data_classification=args.classification)).ask(
            args.question
        )
    print("LLM saw:\n" + (trace.llm_prompt or "(nothing - blocked before the model)"))
    print("\nTool calls:", trace.tool_calls)
    print("\nAnswer:", trace.answer)
    if trace.blocked:
        print("Blocked at", trace.blocked)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
