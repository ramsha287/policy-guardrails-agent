# How to use it

A walkthrough for the people who use the platform day to day. It covers the console, reviewing
held requests, changing guardrails, and connecting an agent. To get an admin key, see
[production.md](production.md#how-a-new-person-gets-a-key).

## 1. Sign in

Open `/console/` on the control plane's address (locally: http://localhost:8200/console/) and
paste your admin key (`cpk_…`). The key stays in that browser tab only, so closing the tab signs
you out. The **Sign out** button in the menu also forgets it.

The menu only shows what your key is allowed to do. A reviewer sees the review queue, for
example, but not the pipeline editing buttons.

## 2. Find your way around

| Screen | Use it to |
| --- | --- |
| **Overview** | See today's traffic, blocks, held requests waiting and gateway health at a glance |
| **Review queue** | Decide requests that a guardrail held for a person (escalations) |
| **Publish approvals** | Approve or reject production changes requested by another admin |
| **Pipeline** | Choose which guardrails run per environment and stage, in shadow or enforce mode, then publish or roll back |
| **Simulate** | Try a payload against a pipeline without affecting anything |
| **Guardrails** | See registered guardrails, their versions and which gateways have them installed |
| **Tenants & keys** | Manage tenants, agents (trust score, allowed tools), actions, and the agents' gateway keys |
| **Gateways** | Check each gateway: last heartbeat, config version, health |
| **Analytics** | Decisions over time, by guardrail, agent and stage |
| **Activity log** | Who changed what, and when (platform admins) |
| **Admin keys** | Give people access, and revoke it |

## 3. Review a held request

When a guardrail isn't sure, it returns **escalate**. The agent's request waits for up to 15
minutes, and if nobody decides in time it's blocked.

1. Open **Review queue**. The newest pending items are at the top, with a countdown.
2. Click a row. **Why it was held** shows the guardrail, its reason and what it found (for
   example `EMAIL_ADDRESS`), with a redacted preview of the payload.
3. Add a note (optional, but it helps the audit trail) and click **Approve** or **Reject**.
   - Approve: the agent carries on.
   - Reject: the request stays blocked.

With the `reviewer-raw` role, **Show raw payload** shows the original text after you confirm.
Every raw view is logged.

## 4. Change which guardrails run

1. Open **Pipeline** and pick the environment (dev, staging, production).
2. For each stage, add or remove guardrails, change their order, or switch a guardrail's
   mode:
   - `shadow`: it runs and is logged, but can't change the outcome.
   - `enforce`: its decision counts.
3. Click **Review & publish** to see exactly what changes.
   - **dev / staging**: **Publish** goes live on the gateways within seconds.
   - **production**: **Request publish** sends it to **Publish approvals**, and a different
     admin approves it.
4. Something wrong? Every published version can be rolled back from the Pipeline page.

A safe routine for a new or changed guardrail: put it in `shadow`, watch **Analytics** for a
few days, try edge cases in **Simulate**, then switch it to `enforce`.

## 5. Try something without risk: Simulate

Pick the environment and stage, choose an agent and action, paste a payload and click **Run
simulation**. You see the decision, each guardrail's result, the scores, what OPA said, and the
redacted payload. Nothing is enforced or audited.

## 6. Connect an agent

1. **Tenants & keys** → choose the tenant → register the agent (trust score, allowed tools).
2. **New API key** → copy the `gk_…` key. It's shown only once.
3. In the agent, either:
   - **No code changes (proxy mode):** point your OpenAI client at the gateway:
     ```python
     from openai import OpenAI
     client = OpenAI(base_url="https://<gateway>/v1", api_key="gk_...")
     ```
   - **Full control (SDK):** call the gateway at each stage:
     ```python
     from guardrail_sdk import GuardClient, GuardHooks, GuardrailBlocked

     async with GuardClient("https://<gateway>", "gk_...", agent_id="research-agent") as client:
         hooks = GuardHooks(client, user_id=user_id, data_classification="PII")
         try:
             prompt = await hooks.before_llm(user_text)             # input
             chunks = await hooks.on_retrieval(search(prompt))      # retrieval
             answer = await hooks.after_llm(await llm(prompt, chunks))  # output
         except GuardrailBlocked as exc:
             answer = f"Request blocked: {exc.reason}"
     ```

   For tools, LangGraph and CrewAI, see [agent-integration.md](agent-integration.md).

## 7. What the agent gets back

| Decision | What the agent should do |
| --- | --- |
| `allow` | Carry on |
| `modify` | Carry on, using the returned (redacted) payload |
| `block` | Stop and show the reason. The SDK raises `GuardrailBlocked` |
| `escalate` | A person is deciding. With `wait_for_review_seconds` set, the SDK hooks wait for the decision; otherwise they raise `GuardrailEscalated` with an `escalation_id` to check later |

If anything goes wrong inside the platform (a guardrail times out, the policy engine is down,
no configuration is loaded), the answer is **block**. The platform fails closed in every
environment, so problems show up in testing instead of passing silently.

## Common questions

**I lost my admin key.** Ask an admin to revoke it and create a new one. Keys can't be recovered.

**An agent gets `401`.** Its gateway key is wrong or revoked. Check **Tenants & keys**.

**An agent gets `429`.** It's over its rate limit. Wait for `Retry-After`, or raise the key's
limit in **Tenants & keys**.

**Everything is blocked in production for PII data.** The policy requires `ai-gateway-pii` to be
*enforced* for `PII` and `CONFIDENTIAL` data. If it's still in `shadow`, switch it to `enforce`.

**My change isn't live.** Check **Gateways**: each gateway shows the config version it's running.
For production, check that the publish was approved.
