# Connecting an agent

Agents call the gateway at four points. The SDK hooks make each point a single call. Each
hook returns the value that is safe to use, or raises `GuardrailBlocked`.

| Hook | Stage | Call it | What can happen |
| --- | --- | --- | --- |
| `before_llm(prompt)` | input | Before the model sees user text or messages | redacted, or blocked |
| `on_retrieval(chunks)` | retrieval | After search, before chunks go into the prompt | chunks redacted or dropped, or blocked |
| `before_tool(name, args)` | tool | Before a tool runs | denied by policy (tool not allowed), arguments redacted, or PII to an external tool blocked |
| `after_tool(name, args, result)` | tool | After a tool returns, before the model sees the result | result redacted, or blocked |
| `after_llm(text)` | output | Before the answer reaches the user | redacted, or blocked |

```bash
pip install -e packages/guardrail-sdk      # PyPI package later
```

## Plain Python (async)

```python
from guardrail_sdk import GuardClient, GuardHooks, GuardrailBlocked

async with GuardClient("http://guardrail-gateway:8100", api_key, agent_id="research-agent") as client:
    hooks = GuardHooks(client, data_classification="PII")
    user_hooks = hooks.with_context(user_id=user.id, session_id=session.id)   # per request
    try:
        prompt = await user_hooks.before_llm(question)
        docs = await user_hooks.on_retrieval(chunks)
        answer = await user_hooks.after_llm(await llm(prompt, docs))
    except GuardrailBlocked as exc:
        answer = "Sorry, I can't help with that."   # exc.response has stage, reason, results
```

Synchronous code uses `SyncGuardClient` and `SyncGuardHooks`, which have the same methods.

## Tools (any framework)

Put `guard_tool` **under** the framework's decorator, so the framework still sees the original
signature and docstring:

```python
from langchain_core.tools import tool
from guardrail_sdk.integrations import guard_tool

@tool
@guard_tool(hooks, name="crm.lookup")
async def crm_lookup(email: str) -> dict:
    """Look up a customer by email."""
    ...
```

The tool only ever receives the checked arguments, and the model only sees the checked result.
A tool that isn't on the agent's `allowed_tools` list is denied by OPA before it runs.
Any tool matching `external_tools` (default `http.*`, `email.*`, `slack.*`, `webhook.*`) is blocked
if its arguments contain PII.

## LangGraph

```python
from langgraph.graph import StateGraph, MessagesState, START, END
from guardrail_sdk.integrations.langgraph import input_guard_node, output_guard_node, guard_retriever

graph = StateGraph(MessagesState)
graph.add_node("guard_in", input_guard_node(hooks, on_block="respond"))
graph.add_node("agent", call_model)                 # tools wrapped with guard_tool
graph.add_node("guard_out", output_guard_node(hooks))
graph.add_edge(START, "guard_in")
graph.add_edge("guard_in", "agent")
graph.add_edge("agent", "guard_out")
graph.add_edge("guard_out", END)

search = guard_retriever(hooks, retriever.ainvoke)  # returns checked Documents
```

The guard nodes replace the latest human or AI message **by id**, so the `add_messages` reducer
updates the message in place. With `on_block="raise"` (the default), a block stops the graph. With
`on_block="respond"`, the node appends a refusal message instead (requires `langchain_core`).
If you route to END on a block, a clean graph skips the model entirely.

## CrewAI

```python
from guardrail_sdk import SyncGuardClient, SyncGuardHooks
from guardrail_sdk.integrations.crewai import guard_crewai_tool, guard_inputs, guard_output

hooks = SyncGuardHooks(SyncGuardClient(url, key, agent_id="support-bot"), data_classification="PII")
agent = Agent(role="Support", tools=[guard_crewai_tool(CrmLookupTool(), hooks)], ...)
result = crew.kickoff(inputs=guard_inputs(hooks, {"question": question}))
answer = guard_output(hooks, result)
```

With `@CrewBase`, call `guard_inputs` in a `@before_kickoff` method and `guard_output` in an
`@after_kickoff` method.

## Sample agent

`examples/sample_agent/agent.py` is a small agent without a framework that uses all four stages.
Its "LLM" repeats back its prompt, so you can see exactly what the model would have received:

```bash
pip install -e packages/guardrail-sdk
export GUARDRAIL_API_KEY=gk_...     # DEMO_GATEWAY_API_KEY from /bootstrap/dev.env
python examples/sample_agent/agent.py "Summarise escalations for jane.doe@example.com"
python examples/sample_agent/agent.py "Please send my number +1 212 555 0199 to the partner"   # blocked at tool
```

`tests/e2e/test_sample_agent.py` runs the same agent against the live stack. Set
`GUARDRAIL_E2E_URL` and `GUARDRAIL_E2E_KEY` to run it; CI does this on every push to `main`.
