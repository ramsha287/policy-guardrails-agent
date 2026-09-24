# ReviewWaitingTooLong / ReviewsExpiringUndecided

**What it means.** Requests escalated to a person are waiting, or have expired without a
decision. Expired items are **blocked**, so the agent got a refusal.

**Act**

1. Open the console's **Review queue** (it shows pending items first, with a countdown).
2. If a tenant has no reviewers online, create a reviewer key for them
   (Admin keys → New admin key → role `reviewer`, scope the tenant).
3. If one guardrail escalates far too often, look at its decisions in Analytics. It may need a
   tuned threshold, or `shadow` mode, before it floods reviewers.

**Settings**: `controlPlane.reviewTtlMinutes` (default 15). Agents that can wait longer can pass
`wait_for_review_seconds` in the SDK hooks.
