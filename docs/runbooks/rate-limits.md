# GatewayRateLimiting

**What it means.** A tenant's API keys are over their per-minute limit, and the gateway answers
429 with `Retry-After`.

**Check.** In the console's Tenants & keys page, each key shows its limit (`default` means
`gateway.rateLimitPerMinute`). The limit applies per key, and the chart divides the global value
across gateway replicas.

**Act.** If the traffic is legitimate, raise that key's limit (Tenants & keys → Limit) or the
global default. If not, revoke the key.
