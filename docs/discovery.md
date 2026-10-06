# Agent discovery and inventory

Discovery finds the AI agents that exist in your environments, including the ones nobody
registered, and compares them with the registry (the agent profiles under Tenants & keys). Each
agent ends up in one of four states:

| State | Meaning | What happens |
| --- | --- | --- |
| **Managed** | Registered, and calling through the guardrail gateway; no bypass seen | Nothing |
| **Registered, unmanaged** | Registered, but seen calling a model provider around the gateway, or never seen at it | `unmanaged_agent` finding (medium) |
| **Shadow** | Behaves like an agent; no registry entry | `shadow_agent` finding (high in production) or `probable_shadow_agent` |
| **Stale** | Registered, but no connector has seen it for 30 days | `stale_agent` finding (low) |

Everything else the connectors find (tools, data stores, model providers, credentials, MCP
servers, identities) is kept too, with the relations between them, so you can answer "what can
this agent reach?" and "what changed since Tuesday?".

No single source sees everything, so discovery never trusts one. Each entity keeps the sources
that reported it, the signals each one gave and the raw observations behind them.

Try it on the Docker Compose stack with the discovery steps in [testing.md](testing.md#discovery-and-inventory-on-the-live-stack).

## How it works

```text
connector run ─► observations ─► entities ─► classification ─► reconciliation ─► state + findings
 (one source,     (evidence:      (merged by    (deterministic     (against the        (+ events,
  read-only)       names, counts)  strong keys)  rules + reasons)   registry)           metrics)
                                       │
                                       └─► relations (temporal edges: valid_from / valid_to)
```

1. **Connectors** read one source each with read-only access and report observations. Each
   observation carries facts: entities with keys and classification signals, and the relations
   between them. Connectors never see the database, and the database never sees a credential.
2. **Entity resolution** merges facts by *strong keys*: an ARN, a Kubernetes workload path, an
   agent id, an API key id, an MCP server URL. Two entities that turn out to share a strong key are
   merged, so the inventory has no duplicates. *Weak keys* (IP addresses, MCP hosts) never merge:
   they only list *probable matches* (a DNS source with the same IP as a pod, for example).
3. **Classification** decides whether an entity is an agent from the signals all its sources gave
   (table below). Every decision carries its reasons in plain words.
4. **Reconciliation** links agents to the registry, by the strong key `agent:<agent_id>`
   (gateway traffic, the Kubernetes label `guardrails.io/agent-id`, the AWS tag
   `guardrails.io/agent-id`), by a manual link, or by an OpenAI service-account name equal to a
   registered agent id. Then it sets the state and opens or resolves findings.
5. **Relations** are versioned: a changed relation closes the old row and opens a new one, so
   the graph can be read "as of" any time.

| Signal | From |
| --- | --- |
| `registered` | the registry |
| `gateway_client` | gateway traffic for the agent id; SDK or proxy settings (`GUARDRAIL_GATEWAY_URL`, a gateway host) |
| `agent_runtime` | Bedrock agents, AgentCore runtimes, kagent `Agent` resources |
| `agent_framework` | LangChain/LangGraph, CrewAI, AutoGen, LlamaIndex, Agents SDK... (variable names, images) |
| `mcp_client` | MCP variables or URLs, lookups of MCP hosts |
| `calls_model` | provider keys or endpoints, lookups of provider hosts, used OpenAI keys, gateway LLM stages |
| `direct_model_access` | calls a provider and has no sign of the gateway (a bypass) |
| `uses_tools` | data-store and SaaS variables, tool calls at the gateway, action groups, MCP servers |
| `llm_server` | vLLM, Ollama, TGI, llama.cpp, LocalAI... (infrastructure, not an agent) |
| `human_identity` | a person's key (never an agent) |

| Classification | Rule |
| --- | --- |
| confirmed agent | registered; or an agent runtime; or seen at the gateway as an agent; or calls a model **and** uses tools/data; or calls a model with an agent framework |
| probable agent | an agent framework alone; an MCP client alone; calls a model with no tool use seen yet |
| not an agent | everything else, people's identities, and LLM servers |

An identity counts as an agent when it calls a model and calls tools or data, runs an agent
framework, or is an MCP client.

**SDK (sidecar) mode is not a bypass.** With the SDK, the agent asks the gateway to check a step
and then calls the model itself. A workload with a provider key *and* gateway settings, or a DNS
source that looks up both a provider and the gateway, is therefore not flagged as
`direct_model_access`.

## Connectors

| Kind | Reads | Finds | Snapshot? |
| --- | --- | --- | --- |
| `gateway` | the gateway's audit log (AUDIT_DSN, read-only) | agents calling through the gateway, with their tools, data stores and external hosts; gateway request volume | no (window) |
| `kubernetes` | pod specs through the Kubernetes API | workloads with model keys, frameworks, MCP use, data access; service accounts; credentials by reference; LLM servers; kagent agents | yes |
| `dns_log` | DNS query logs (Route 53 Resolver, or any JSON lines) | any source resolving model-provider or MCP hosts: the best shadow-agent signal | no (window) |
| `openai_admin` | OpenAI Admin API | projects, service accounts, API keys and their last use | yes |
| `aws_bedrock` | Bedrock Agents and AgentCore control APIs | agents, model, role, guardrail attachment, action groups, knowledge bases, collaborators, runtimes, gateway targets | yes |
| `mcp` | `tools/list` on the MCP servers you name | servers and tools, with a pinned hash of every tool definition | yes |

*Snapshot* sources list everything they have on every run, so after a clean run whatever they
no longer list is treated as removed: its relations close and it loses that source (a deleted
deployment stops being a shadow agent). Window sources report activity in a time window, so
their evidence ages out after 30 days instead. **A run with an error or a warning never removes
anything:** a source that answered half its questions must not make the other half look deleted.

### Credentials

A connector's configuration never holds a secret. Credential fields end in `_env` and name an
environment variable on the control plane whose name starts with `DISCOVERY_SECRET_` (for
example `DISCOVERY_SECRET_OPENAI_ADMIN`). Any other name is refused, so a connector can't be
pointed at `INTERNAL_TOKEN` or a database DSN. With Helm, put the values in the platform Secret
and list the keys in `controlPlane.discovery.secretKeys`.

### gateway

```json
{"lookback_hours": 24, "environment": null, "max_rows": 20000}
```

Needs `AUDIT_DSN` on the control plane (the same DSN analytics uses; give it a read-only user outside dev). One observation
per agent and environment: request count, blocked count, assurance (A0/A1), and from the action
descriptors the tools it called, the tables or files it read or wrote and the external hosts it
sent to. This is what makes an agent *managed*. Run it first.

### kubernetes

```json
{"cluster": "prod-1", "namespaces": [], "label_selector": null, "include_kagent": true,
 "gateway_hosts": ["guardrail-gateway"], "api_url": "https://kubernetes.default.svc", "token_env": null}
```

In-cluster (Helm `controlPlane.discovery.kubernetes.enabled: true`) it uses the control plane's
own service account with this ClusterRole, and nothing else:

```yaml
rules:
  - {apiGroups: [""], resources: [pods], verbs: [get, list]}
  - {apiGroups: [kagent.dev], resources: [agents], verbs: [get, list]}
```

The ClusterRole covers every namespace and every tenant's Kubernetes connector uses it, so on a
shared cluster give it to one tenant or set `namespaces` (DNS labels) per connector. The chart
requires `controlPlane.discovery.kubernetes.apiServerCIDRs` so the egress rule is pinned to the
API server.

For another cluster, set `api_url`, `ca_file` and `token_env` (a read-only token in a
`DISCOVERY_SECRET_*` variable); `token_env` is required there, because the pod's own
service-account token is only ever sent to `https://kubernetes.default.svc`. It reads variable **names**, plain values that are URLs, images,
labels, the service account and pod IPs. `valueFrom` secrets are recorded as a reference
(`namespace/secret#key`); secrets and configmaps are never read (the role can't). Label a workload
`guardrails.io/agent-id: <agent_id>` to link it to a registered agent, and `owner` or `team` for the
owner guess.

### dns_log

```json
{"path": "route53/*.log.gz", "format": "route53", "window_hours": 24,
 "mcp_hosts": ["mcp.internal.example"], "gateway_hosts": ["guardrail-gateway"], "max_mb": 200}
```

Turn on [Route 53 Resolver query logging](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html)
to S3, sync the objects to a volume (Helm `controlPlane.discovery.logs.existingClaim`, mounted
read-only at `DISCOVERY_LOG_DIR`), and point `path` at them. Files are only read under that
directory (symlinks out of it are skipped); `.gz` works. Instead of `path`, `url` reads one
HTTPS JSON-lines file. For other resolvers (CoreDNS logs shipped as JSON, a firewall), use
`"format": "jsonl"` with `query_field`, `source_field`, `time_field`, `instance_field` and
`network_field` (dotted paths).

A source is the EC2 instance id when the log has it, otherwise VPC + IP address. Lookups are
counted per provider and MCP host. A lookup is not a request, so coverage reports them as
`dns_lookups`, separately from gateway requests.

### openai_admin

```json
{"admin_key_env": "DISCOVERY_SECRET_OPENAI_ADMIN", "active_days": 30, "include_user_keys": false,
 "match_agent_names": true}
```

Uses an OpenAI Admin key (read-only use: projects, service accounts, API keys). There is no OpenAI
API that lists "agents"; a project service account with a key used in the last `active_days` is a
probable agent. People's keys are left out unless `include_user_keys`. With `match_agent_names`, a
service account named like a registered agent id is linked to it.

### aws_bedrock

```json
{"regions": ["us-east-1", "eu-west-1"], "assume_role_arn": null, "external_id": null,
 "bedrock_agents": true, "agentcore": true, "agent_version": "DRAFT"}
```

Uses the control plane's AWS credentials (IRSA, instance profile or environment), optionally
assuming `assume_role_arn`. A policy with only what it calls:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "bedrock:ListAgents", "bedrock:GetAgent", "bedrock:ListAgentActionGroups",
      "bedrock:ListAgentKnowledgeBases", "bedrock:ListAgentCollaborators", "bedrock:ListTagsForResource",
      "bedrock-agentcore:ListAgentRuntimes", "bedrock-agentcore:ListGateways",
      "bedrock-agentcore:ListGatewayTargets"
    ],
    "Resource": "*"
  }]
}
```

A Bedrock agent without a guardrail shows `guardrail_attached: false` in its evidence. Tag it
`guardrails.io/agent-id` to link it to a registered agent. AgentCore APIs are still changing; a
call that fails becomes a warning on the run and the rest of the run continues.

### mcp

```json
{"servers": [{"url": "https://mcp.example.internal/mcp", "name": "crm",
              "auth_header": "Authorization", "auth_env": "DISCOVERY_SECRET_MCP_CRM", "owner": "crm-team"}]}
```

Runs `initialize` and `tools/list` (Streamable HTTP, JSON or event-stream responses) on each
server and never calls a tool. Each tool's name, description and input schema are hashed. The
first hash seen is *pinned*. A different hash later opens a high-severity
`tool_definition_changed` finding with the old and new description (the console shows both in the Findings view): this is how a tool
that changes after you approved it (a "rug pull", tool poisoning) shows up. **Accept** the finding
to pin the new definition; if the server goes back to the pinned one, the finding resolves itself.
Until then, calls to that tool carry `TOOL_DEFINITION_CHANGED` (+25) at the gateway.

## Using the inventory

The console's **Agent inventory** page shows coverage, the agents by state, every entity and the
open findings. Open an entity for its reasons, the sources and signals behind it, its relations,
its evidence and its findings. From there:

- **Register agent** creates the registry entry (`catalog:write`) and links the entity. A shadow
  agent then becomes managed once it calls through the gateway with a key bound to it.
- **Link to a registered agent** says "this workload (or identity) *is* agent X". The entity takes
  the key `agent:X` and merges with X's own entry.
- **Ignore** suppresses findings for a number of days, with a reason (a load-test harness, say).
- **Findings:** *accept* (known and fine; not raised again for that item) or *resolve* (fixed).
  Only an open finding can be accepted or resolved; an accepted or resolved one can be reopened.
  Automatic findings also resolve themselves when their cause goes away, and a
  `tool_definition_changed` finding resolves when no server lists the tool any more.

**Discovery connectors** (Configure) lists the sources with their last run. Platform admins add,
edit and delete connectors; tenant editors can *Run now*. Each run records its counts, warnings
and error.

**Coverage** is the share of active agents (seen by a connector in the last 30 days, not stale)
that are managed. Request volume through the gateway and model traffic seen outside it are shown
next to it, in their own units.

## API

`X-Admin-Key` like the rest of the control-plane API; tenant keys see their own tenant.

| Endpoint | Who |
| --- | --- |
| `GET /inv/v1/connector-kinds` | read |
| `GET/POST /inv/v1/tenants/{t}/connectors`, `GET/PATCH/DELETE …/connectors/{id}` | read / `discovery:write` (platform admins) |
| `POST …/connectors/{id}/sync`, `GET …/connectors/{id}/runs` | `inventory:write` / read |
| `GET …/entities?kind=&state=&agents_only=&q=`, `GET …/entities/{id}` | read |
| `GET …/entities/{id}/graph?depth=2&as_of=2026-10-01T12:00:00Z` | read |
| `POST …/entities/{id}/link` `{"agent_id"}`, `…/register` `{"agent_id","base_trust_score"}`, `…/ignore` `{"reason","days"}` | `inventory:write` (+ `catalog:write` to register) |
| `GET …/coverage?environment=`, `GET …/summary` | read |
| `GET …/findings?status=open|accepted|resolved|all&kind=`, `PATCH …/findings/{id}` `{"status","note"}` | read / `inventory:write` |
| `POST …/reconcile` | `inventory:write` |

`inventory:write` is in the `editor` and `admin` roles; `discovery:write` in `admin` and only for
platform keys. Keys without `discovery:write` get connectors with an empty `config` (URLs, account
ids and secret variable names are for those who manage them). `as_of` without an offset is UTC.

CLI (for cron or CI): `python -m app.cli discovery-sync [--tenant acme] [--connector ID]` (exit 1
if a run failed) and `python -m app.cli discovery-reconcile [--tenant acme]`.

**Events:** state changes and new findings are published on the Redis channel
`guardrail:inventory.changed` (`inventory.entity.state_changed.v1`, `inventory.finding.opened.v1`)
when the control plane has `REDIS_URL`. Route them to the owner (the *notify* step of the
shadow-agent response ladder).

**Metrics:** `cp_inventory_agents{state}`, `cp_inventory_findings_open{severity}`,
`cp_discovery_runs_total{kind,status}`, `cp_discovery_connectors_failing`.

## Security model

- Connectors are read-only by construction: list/get APIs, one read-only query on the audit log,
  `tools/list` only, file reads under one directory. They never call a tool, read a secret value or
  store payload text.
- Creating or changing a connector is platform-only (`discovery:write`): connectors hold
  infrastructure credentials and call URLs.
- Credentials are `DISCOVERY_SECRET_*` variables, never stored or returned by the API.
- Every URL a connector calls is checked first: cloud metadata addresses, loopback, link-local and
  reserved addresses are refused, plain `http://` is refused unless `DISCOVERY_ALLOW_HTTP=true`
  (labs), and redirects are not followed. The check resolves the name before the request, so DNS
  rebinding is not covered: keep the control plane's egress behind the chart's NetworkPolicy.
- One run per connector at a time across replicas (a lease in the database); a crashed run's
  lease expires after 30 minutes. A scheduler tick claims a connector only if it is still due,
  so two replicas never run it back to back; editing a connector never touches its lease.
- Inventory writes for a tenant are serialised (a Postgres advisory lock per tenant): runs of
  different connectors, reconciles and operator actions apply one at a time, so concurrent
  runs can't open duplicate findings. Collection itself still runs in parallel.
- Remote text is sanitised before it is stored (NUL characters dropped, lengths capped); gzip
  logs fetched from a URL are decompressed only up to `max_mb`.

## Settings

| Variable | Helm value | Default | Meaning |
| --- | --- | --- | --- |
| `DISCOVERY_SCHEDULER` | `controlPlane.discovery.scheduler` | `true` | Run due connectors in this process |
| `DISCOVERY_TICK_SECONDS` | `controlPlane.discovery.tickSeconds` | `60` | How often the scheduler looks for due connectors |
| `DISCOVERY_MAX_OBSERVATIONS` | `controlPlane.discovery.maxObservations` | `20000` | Per run; more makes the run partial |
| `DISCOVERY_ALLOW_HTTP` | `controlPlane.discovery.allowHttp` | `false` | Allow plain http:// connector URLs |
| `DISCOVERY_LOG_DIR` | set by `controlPlane.discovery.logs.existingClaim` | `/var/lib/guardrail-discovery/logs` | Where `dns_log` may read files |
| `DISCOVERY_SECRET_*` | `controlPlane.discovery.secretKeys` | — | Connector credentials |
| `AUDIT_DSN` | `controlPlane.analytics` | — | Needed by the `gateway` connector |

Data: schema `inventory` (control-plane migration `0004`): `connectors`, `sync_runs`,
`observations` (pruned after 90 days), `entities`, `edges`, `findings`.

## Findings feed the gateway's risk

The control plane publishes two things from the inventory in the catalog the gateways already
poll, and the gateway turns them into capped risk signals:

| Catalog field | From | Gateway signal |
| --- | --- | --- |
| `agents[].open_findings` | open `unmanaged_agent` findings on a registered agent (it also reaches models without the gateway) | `AGENT_FINDING` (+20) on that agent's requests |
| `flagged_tools` | open `tool_definition_changed` findings, as `<server>/<tool>` (an MCP tool changed after it was approved) | `TOOL_DEFINITION_CHANGED` (+25) on a call to that tool |

A bare tool name (`lookup_customer`) matches, since the call doesn't say which server it means. A
qualified name (`crm__lookup_customer`, `mcp__crm__lookup_customer`, `crm/lookup_customer`,
`crm:lookup_customer`) matches only when its server part is that server, so a changed `query` on
one MCP server doesn't raise the risk of every `catalog.query` in the tenant. The catalog is republished
after every run, reconcile and finding change; accepting or resolving the finding removes the
signal within a catalog poll. Weights are `agent_finding` and `tool_definition_changed` in
`RISK_CONFIG_JSON`.

Older gateways reject unknown catalog fields, so the control plane leaves both out while any
gateway heard from in the last 15 minutes doesn't report the `inventory_risk_v1` capability
(0.10+). A gateway joining, coming back or upgrading triggers a republish from its heartbeat, so
the fields disappear and reappear without waiting for another change.

## Known limits

- Sources so far: our gateway, Kubernetes, DNS logs, OpenAI, Bedrock/AgentCore, MCP. CloudTrail
  invocation logs, Azure (Foundry, Entra Agent ID), Google Cloud and code/SBOM scanning are next.
- Findings raise risk on the gateway ([above](#findings-feed-the-gateways-risk)) but nothing acts
  on a shadow workload outside the gateway yet: denying its egress to model providers (the
  response ladder's tier-1 step) comes with the response engine.
- DNS lookups are a proxy for traffic, not a count of requests; resolvers cache, and traffic
  through an unknown proxy shows the proxy, not the agent.
- Linking by name (OpenAI service accounts) and by label or tag trusts whoever sets them; check
  the evidence before registering.
- Reconciliation reads the whole tenant inventory on every run. That is fine into the tens of
  thousands of entities; beyond that it needs incremental reconciliation.
