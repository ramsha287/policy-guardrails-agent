"""Walk the text in a payload and put rewritten text back, keeping the payload's shape.

Shared by the local content guardrails (secrets, prompt-injection, topic-limits, moderation). Each
span has a display `location`, named like findings everywhere else:

    text · messages[2] · chunks[c-7] · tool_call.arguments.query · tool_call.result.rows[0].note

and a structural `key` (a tuple path such as ("arguments", "opts", "tags", 1)). Rewrites are keyed
by `key`, never by the display string, because display strings can collide: a dict key containing
"." or "[" and a nested key print the same, and chunk ids needn't be unique.

Only string leaves are visited. Dict keys are not rewritten (they are structure, not content).
At most `limit` characters per payload are scanned so a huge payload can't stall the event loop;
the rest is reported as `truncated` (guardrails decide what that means for them).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from guardrail_sdk import Payload

DEFAULT_LIMIT = 512 * 1024
Key = tuple[Any, ...]


@dataclass(frozen=True)
class Span:
    location: str
    text: str  # what is scanned (a prefix of `full` when the budget ran out)
    key: Key = ()
    role: str | None = None  # message role, for messages[i]
    full: str | None = None  # the whole original text; rewrite from this, not from `text`

    @property
    def original(self) -> str:
        return self.full if self.full is not None else self.text

    @property
    def partial(self) -> bool:
        return self.full is not None


@dataclass
class Walk:
    spans: list[Span]
    truncated: bool = False


def _json_leaves(value: Any, path: str, key: Key) -> Iterator[tuple[str, Key, str]]:
    if isinstance(value, str):
        yield path, key, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _json_leaves(v, f"{path}.{k}", (*key, k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _json_leaves(v, f"{path}[{i}]", (*key, i))


def walk(
    payload: Payload,
    *,
    tool_arguments: bool = True,
    tool_result: bool = True,
    roles: frozenset[str] | None = None,
    limit: int = DEFAULT_LIMIT,
) -> Walk:
    """The text spans of a payload, in a stable order. `roles` limits which messages are visited."""
    out: list[Span] = []
    budget = limit
    truncated = False

    def add(location: str, key: Key, text: str, role: str | None = None) -> None:
        nonlocal budget, truncated
        if budget <= 0:
            truncated = True
            return
        full = None
        if len(text) > budget:
            truncated = True
            full, text = text, text[:budget]
        budget -= len(text)
        out.append(Span(location, text, key, role, full))

    if payload.text is not None:
        add("text", ("text",), payload.text)
    for i, m in enumerate(payload.messages or []):
        if roles is None or m.role in roles:
            add(f"messages[{i}]", ("messages", i), m.content, m.role)
    for i, c in enumerate(payload.chunks or []):
        add(f"chunks[{c.id}]", ("chunks", i), c.text)
    tc = payload.tool_call
    if tc is not None:
        if tool_arguments:
            for loc, key, s in _json_leaves(tc.arguments, "tool_call.arguments", ("arguments",)):
                add(loc, key, s)
        if tool_result and tc.result is not None:
            for loc, key, s in _json_leaves(tc.result, "tool_call.result", ("result",)):
                add(loc, key, s)
    return Walk(out, truncated)


def _rewrite_json(value: Any, key: Key, new: dict[Key, str]) -> Any:
    if isinstance(value, str):
        return new.get(key, value)
    if isinstance(value, dict):
        return {k: _rewrite_json(v, (*key, k), new) for k, v in value.items()}
    if isinstance(value, list):
        return [_rewrite_json(v, (*key, i), new) for i, v in enumerate(value)]
    return value


def rewrite(payload: Payload, new: dict[Key, str], *, drop_chunks: frozenset[int] = frozenset()) -> Payload:
    """A copy of `payload` with the text at the given span keys replaced, and the chunks at the
    given positions dropped. The shape is unchanged (same fields, roles, tool name; chunks only
    ever removed)."""
    update: dict[str, Any] = {}
    if payload.text is not None and ("text",) in new:
        update["text"] = new[("text",)]
    if payload.messages is not None:
        update["messages"] = [
            m.model_copy(update={"content": new.get(("messages", i), m.content)})
            for i, m in enumerate(payload.messages)
        ]
    if payload.chunks is not None:
        update["chunks"] = [
            c.model_copy(update={"text": new.get(("chunks", i), c.text)})
            for i, c in enumerate(payload.chunks)
            if i not in drop_chunks
        ]
    tc = payload.tool_call
    if tc is not None:
        update["tool_call"] = tc.model_copy(
            update={
                "arguments": _rewrite_json(tc.arguments, ("arguments",), new),
                "result": _rewrite_json(tc.result, ("result",), new) if tc.result is not None else None,
            }
        )
    return payload.model_copy(update=update)
