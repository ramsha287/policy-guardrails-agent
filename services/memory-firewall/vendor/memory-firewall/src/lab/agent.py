"""Deterministic lab agent (no LLM) whose decisions depend on its long-term memory.

Scenario: a refund assistant. It remembers policy facts across sessions (for example
``refund_limit``) and later approves or rejects refund requests using those facts. If its
checkpointed memory is silently altered, its decisions change — which is exactly what the
memory firewall must prevent.

Every call to ``graph.invoke`` writes several checkpoints (input, after each node) plus
pending writes, so it exercises all of LangGraph's checkpoint write paths.
"""

import operator
from typing import Annotated, Literal, NotRequired, TypedDict

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph


def merge_facts(old: dict[str, str], new: dict[str, str]) -> dict[str, str]:
    return {**old, **new}


class Event(TypedDict):
    kind: Literal["remember", "refund"]
    key: NotRequired[str]
    value: NotRequired[str]
    amount: NotRequired[int]


class AgentState(TypedDict):
    event: Event
    facts: Annotated[dict[str, str], merge_facts]  # long-term memory
    history: Annotated[list[str], operator.add]  # audit trail of what the agent did
    decision: str


def ingest(state: AgentState) -> dict:
    e = state["event"]
    return {"history": [f"in:{e['kind']}"]}


def route(state: AgentState) -> str:
    return "remember" if state["event"]["kind"] == "remember" else "decide"


def remember(state: AgentState) -> dict:
    e = state["event"]
    return {"facts": {e["key"]: e["value"]}, "history": [f"remember:{e['key']}"], "decision": "stored"}


def decide(state: AgentState) -> dict:
    amount = state["event"]["amount"]
    limit = int(state.get("facts", {}).get("refund_limit", "0"))
    decision = "approve" if amount <= limit else "reject"
    return {"history": [f"refund:{amount}:{decision}"], "decision": decision}


def build_agent(checkpointer: BaseCheckpointSaver):
    g = StateGraph(AgentState)
    g.add_node("ingest", ingest)
    g.add_node("remember", remember)
    g.add_node("decide", decide)
    g.add_edge(START, "ingest")
    g.add_conditional_edges("ingest", route, ["remember", "decide"])
    g.add_edge("remember", END)
    g.add_edge("decide", END)
    return g.compile(checkpointer=checkpointer)


def thread_config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


def remember_event(key: str, value: str) -> dict:
    return {"event": {"kind": "remember", "key": key, "value": value}}


def refund_event(amount: int) -> dict:
    return {"event": {"kind": "refund", "amount": amount}}
