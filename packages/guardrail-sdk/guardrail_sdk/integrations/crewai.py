"""CrewAI adapters (synchronous, like CrewAI tools).

    from guardrail_sdk.hooks import SyncGuardClient, SyncGuardHooks
    from guardrail_sdk.integrations.crewai import guard_crewai_tool, guard_inputs, guard_output

    hooks = SyncGuardHooks(SyncGuardClient(url, key, agent_id="support-bot"), data_classification="PII")
    crm = guard_crewai_tool(CrmLookupTool(), hooks)           # checks arguments and result
    result = crew.kickoff(inputs=guard_inputs(hooks, {"question": question}))
    answer = guard_output(hooks, result)                        # checks the final answer

With `@CrewBase` classes, call `guard_inputs` in a `@before_kickoff` method and `guard_output`
in an `@after_kickoff` method.
"""

from __future__ import annotations

from typing import Any

from ..hooks import SyncGuardHooks


def guard_crewai_tool(tool: Any, hooks: SyncGuardHooks, *, name: str | None = None) -> Any:
    """Wrap a CrewAI BaseTool instance in place: its `_run` is checked before and after the call."""
    original = tool._run
    tool_name = name or getattr(tool, "name", None) or type(tool).__name__

    def _run(*args: Any, **kwargs: Any) -> Any:
        if args:
            kwargs = {**{f"arg{i}": a for i, a in enumerate(args)}, **kwargs}
        safe_args = hooks.before_tool(tool_name, kwargs)
        positional = [safe_args.pop(f"arg{i}") for i in range(len(args))]
        result = original(*positional, **safe_args)
        return hooks.after_tool(tool_name, safe_args, result)

    object.__setattr__(tool, "_run", _run)  # pydantic models block plain setattr on unknown attrs
    return tool


def guard_inputs(hooks: SyncGuardHooks, inputs: dict[str, Any]) -> dict[str, Any]:
    """Input stage for every string value of a kickoff `inputs` dict."""
    return {k: hooks.before_llm(v) if isinstance(v, str) and v.strip() else v for k, v in inputs.items()}


def guard_output(hooks: SyncGuardHooks, output: Any) -> str:
    """Output stage for a CrewOutput (uses `.raw`) or a plain string."""
    text = getattr(output, "raw", output)
    return hooks.after_llm(str(text))
