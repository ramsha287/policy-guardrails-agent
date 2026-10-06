// Labels, tones and helpers for the agent inventory screens (kept free of React for unit tests).

import type { EntityState, Finding, InventoryEntity, RunStatus, Severity, SourceEntry } from "./types";

type Tone = "neutral" | "info" | "good" | "warning" | "serious" | "critical";

export const STATE_LABEL: Record<EntityState, string> = {
  managed: "Managed",
  registered_unmanaged: "Registered, unmanaged",
  shadow: "Shadow",
  stale: "Stale",
  not_agent: "Not an agent",
};

export const STATE_HELP: Record<EntityState, string> = {
  managed: "Registered and calling through the guardrail gateway.",
  registered_unmanaged: "Registered, but calls models or tools around the gateway (or isn't seen at it).",
  shadow: "Behaves like an agent, but nobody registered it.",
  stale: "Registered, but no connector has seen it for 30 days.",
  not_agent: "Part of the inventory (a tool, data store, provider, credential...), not an agent.",
};

export function stateTone(state: EntityState): Tone {
  switch (state) {
    case "managed":
      return "good";
    case "registered_unmanaged":
      return "warning";
    case "shadow":
      return "critical";
    default:
      return "neutral";
  }
}

export function severityTone(s: Severity): Tone {
  return s === "high" ? "critical" : s === "medium" ? "serious" : "warning";
}

export function runTone(s: RunStatus | null | undefined): Tone {
  switch (s) {
    case "ok":
      return "good";
    case "partial":
      return "warning";
    case "error":
      return "critical";
    case "running":
      return "info";
    default:
      return "neutral";
  }
}

export const FINDING_LABEL: Record<string, string> = {
  shadow_agent: "Unregistered agent",
  probable_shadow_agent: "Possible unregistered agent",
  unmanaged_agent: "Bypasses the gateway",
  stale_agent: "Not seen for 30 days",
  tool_definition_changed: "Tool definition changed",
};

/** What each source said about the entity, newest first (the registry last). */
export function sourcesOf(e: InventoryEntity): (SourceEntry & { id: string })[] {
  const entries = Object.entries(e.attrs.by_source ?? {}).map(([id, s]) => ({ ...s, id }));
  return entries.sort((a, b) => {
    if (a.kind === "registry") return 1;
    if (b.kind === "registry") return -1;
    return (b.at ?? "").localeCompare(a.at ?? "");
  });
}

/** A registry agent id suggestion from a discovered name: "apps/crm-bot" -> "crm-bot". */
export function suggestAgentId(name: string): string {
  const last = name.split(/[/\s]+/).filter(Boolean).pop() ?? name;
  const id = last
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 128);
  return id || "agent";
}

export function canBeAgent(kind: string): boolean {
  return ["agent", "workload", "endpoint", "identity"].includes(kind);
}

/** Example configurations for the "new connector" form. Credentials are variable NAMES only. */
export const CONNECTOR_EXAMPLES: Record<string, Record<string, unknown>> = {
  gateway: { lookback_hours: 24 },
  kubernetes: { cluster: "prod-1", namespaces: [], gateway_hosts: ["guardrail-gateway"] },
  dns_log: { path: "route53/*.log.gz", format: "route53", window_hours: 24, mcp_hosts: [] },
  openai_admin: { admin_key_env: "DISCOVERY_SECRET_OPENAI_ADMIN", active_days: 30 },
  aws_bedrock: { regions: ["us-east-1"], bedrock_agents: true, agentcore: true },
  mcp: { servers: [{ url: "https://mcp.example.internal/mcp", auth_env: "DISCOVERY_SECRET_MCP_TOKEN" }] },
};

/** Parses the JSON config field; returns an error message instead of throwing. */
export function parseConfig(text: string): { config?: Record<string, unknown>; error?: string } {
  if (!text.trim()) return { config: {} };
  try {
    const v: unknown = JSON.parse(text);
    if (!v || typeof v !== "object" || Array.isArray(v)) return { error: "The configuration must be a JSON object." };
    return { config: v as Record<string, unknown> };
  } catch (e) {
    return { error: `Not valid JSON: ${e instanceof Error ? e.message : String(e)}` };
  }
}

/** For a changed MCP tool: the approved description and the one the server serves now. */
export function definitionChange(f: Finding): { before: string; after: string } | null {
  if (f.kind !== "tool_definition_changed") return null;
  const d = f.details ?? {};
  const str = (v: unknown) => (typeof v === "string" ? v : "");
  return { before: str(d.old_description), after: str(d.new_description) };
}
