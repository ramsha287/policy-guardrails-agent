"""LangGraph / LangChain adapters (duck-typed: works with langchain_core messages and Documents).

    from guardrail_sdk.integrations.langgraph import input_guard_node, output_guard_node, guard_retriever

    graph = StateGraph(MessagesState)
    graph.add_node("guard_in", input_guard_node(hooks))       # redacts the latest human message
    graph.add_node("agent", call_model)
    graph.add_node("guard_out", output_guard_node(hooks))     # redacts the latest AI message
    graph.add_edge(START, "guard_in"); graph.add_edge("guard_in", "agent")
    graph.add_edge("agent", "guard_out"); graph.add_edge("guard_out", END)

Replacement messages keep the original message `id`, so LangGraph's `add_messages` reducer
replaces the message in state instead of appending a copy. On a block the node either raises
`GuardrailBlocked` (`on_block="raise"`) or appends an AI message with `blocked_message`
(`on_block="respond"`, needs langchain_core).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Literal

from ..hooks import GuardHooks, GuardrailBlocked
from ..models import Chunk

_ROLE = {
    "human": "user",
    "user": "user",
    "ai": "assistant",
    "assistant": "assistant",
    "system": "system",
    "tool": "tool",
}


def _role(msg: Any) -> str | None:
    kind = msg.get("role") if isinstance(msg, dict) else getattr(msg, "type", None)
    return _ROLE.get(str(kind)) if kind is not None else None


def _content(msg: Any) -> Any:
    return msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)


def _with_content(msg: Any, content: str) -> Any:
    if isinstance(msg, dict):
        return {**msg, "content": content}
    if hasattr(msg, "model_copy"):
        return msg.model_copy(update={"content": content})
    msg.content = content
    return msg


def _last(messages: list[Any], role: str) -> int | None:
    for i in range(len(messages) - 1, -1, -1):
        if _role(messages[i]) == role and isinstance(_content(messages[i]), str):
            return i
    return None


def _blocked_reply(text: str) -> Any:
    from langchain_core.messages import AIMessage  # lazy: only needed for on_block="respond"

    return AIMessage(content=text)


def _node(
    hooks: GuardHooks,
    role: str,
    check: Callable[[str], Awaitable[str]],
    messages_key: str,
    on_block: Literal["raise", "respond"],
    blocked_message: str,
) -> Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]:
    async def node(state: dict[str, Any]) -> dict[str, Any]:
        messages = list(state.get(messages_key) or [])
        idx = _last(messages, role)
        if idx is None:
            return {}
        try:
            safe = await check(_content(messages[idx]))
        except GuardrailBlocked:
            if on_block == "raise":
                raise
            return {messages_key: [_blocked_reply(blocked_message)]}
        if safe == _content(messages[idx]):
            return {}
        return {messages_key: [_with_content(messages[idx], safe)]}

    return node


def input_guard_node(
    hooks: GuardHooks,
    *,
    messages_key: str = "messages",
    on_block: Literal["raise", "respond"] = "raise",
    blocked_message: str = "Sorry, I can't help with that request.",
) -> Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]:
    return _node(hooks, "user", hooks.before_llm, messages_key, on_block, blocked_message)


def output_guard_node(
    hooks: GuardHooks,
    *,
    messages_key: str = "messages",
    on_block: Literal["raise", "respond"] = "raise",
    blocked_message: str = "Sorry, I can't share that.",
) -> Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]:
    return _node(hooks, "assistant", hooks.after_llm, messages_key, on_block, blocked_message)


def documents_to_chunks(docs: list[Any]) -> list[Chunk]:
    """langchain_core Documents (page_content, metadata, id) -> chunks. Ids are list positions."""
    return [
        Chunk(
            id=str(i),
            text=getattr(d, "page_content", ""),
            source=(getattr(d, "metadata", None) or {}).get("source"),
        )
        for i, d in enumerate(docs)
    ]


def chunks_to_documents(original: list[Any], chunks: list[Chunk]) -> list[Any]:
    out = []
    for c in chunks:
        doc = original[int(c.id)]
        if hasattr(doc, "model_copy"):
            out.append(doc.model_copy(update={"page_content": c.text}))
        else:
            doc.page_content = c.text
            out.append(doc)
    return out


def guard_retriever(
    hooks: GuardHooks, retrieve: Callable[..., Awaitable[list[Any]]], *, resource: str | None = None
) -> Callable[..., Awaitable[list[Any]]]:
    """Wrap an async retriever (e.g. `retriever.ainvoke`) so documents are checked before use."""

    async def guarded(*args: Any, **kwargs: Any) -> list[Any]:
        docs = await retrieve(*args, **kwargs)
        safe = await hooks.on_retrieval(documents_to_chunks(docs), resource=resource)
        return chunks_to_documents(docs, safe)

    return guarded
