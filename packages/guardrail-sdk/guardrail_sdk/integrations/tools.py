"""`guard_tool`: wrap any Python tool function with before/after tool-stage checks.

Works for plain functions, LangChain/LangGraph `@tool` functions and CrewAI function tools.
Put it *under* the framework decorator so the framework still sees the original signature:

    @tool
    @guard_tool(hooks)
    async def crm_lookup(email: str) -> dict: ...
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from ..hooks import GuardHooks, SyncGuardHooks

F = TypeVar("F", bound=Callable[..., Any])


def guard_tool(
    hooks: GuardHooks | SyncGuardHooks, name: str | None = None, *, resource: str | None = None
) -> Callable[[F], F]:
    def decorator(fn: F) -> F:
        tool_name = name or fn.__name__
        sig = inspect.signature(fn)

        def _arguments(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            return dict(bound.arguments)

        if inspect.iscoroutinefunction(fn):
            if not isinstance(hooks, GuardHooks):
                raise TypeError(f"{tool_name} is async; pass GuardHooks, not SyncGuardHooks")
            async_hooks: GuardHooks = hooks

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                safe_args = await async_hooks.before_tool(tool_name, _arguments(args, kwargs), resource=resource)
                result = await fn(**safe_args)
                return await async_hooks.after_tool(tool_name, safe_args, result, resource=resource)

            return async_wrapper  # type: ignore[return-value]

        if not isinstance(hooks, SyncGuardHooks):
            raise TypeError(f"{tool_name} is synchronous; pass SyncGuardHooks, not GuardHooks")
        sync_hooks: SyncGuardHooks = hooks

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            safe_args = sync_hooks.before_tool(tool_name, _arguments(args, kwargs), resource=resource)
            result = fn(**safe_args)
            return sync_hooks.after_tool(tool_name, safe_args, result, resource=resource)

        return sync_wrapper  # type: ignore[return-value]

    return decorator
