import { describe, expect, it } from "vitest";

import { Api } from "../src/lib/api";
import {
  CONNECTOR_EXAMPLES,
  parseConfig,
  runTone,
  severityTone,
  sourcesOf,
  stateTone,
  suggestAgentId,
} from "../src/lib/inventory";
import type { InventoryEntity } from "../src/lib/types";

function entity(over: Partial<InventoryEntity> = {}): InventoryEntity {
  return {
    id: "e1",
    tenant_id: "acme",
    kind: "workload",
    name: "apps/crm-bot",
    strong_keys: ["k8s:prod/apps/Deployment/crm-bot"],
    weak_keys: [],
    attrs: {
      by_source: {
        registry: { kind: "registry", connector: "registry", signals: ["registered"], attrs: {}, managed: 0, direct: 0 },
        c1: { kind: "kubernetes", connector: "k8s", signals: ["calls_model"], attrs: {}, managed: 0, direct: 0, at: "2026-10-01T10:00:00Z" },
        c2: { kind: "dns_log", connector: "dns", signals: ["calls_model"], attrs: {}, managed: 0, direct: 3, at: "2026-10-02T10:00:00Z" },
      },
    },
    sources: ["c1", "c2", "registry"],
    environment: "production",
    first_seen: "2026-10-01T10:00:00Z",
    last_seen: "2026-10-02T10:00:00Z",
    agent_likelihood: "confirmed",
    reasons: [],
    state: "shadow",
    registry_agent_id: null,
    owner_guess: null,
    managed_volume: 0,
    direct_volume: 3,
    probable_matches: [],
    ignored_until: null,
    ignore_reason: null,
    updated_at: "2026-10-02T10:00:00Z",
    ...over,
  };
}

describe("inventory helpers", () => {
  it("maps states, severities and runs to tones", () => {
    expect(stateTone("managed")).toBe("good");
    expect(stateTone("shadow")).toBe("critical");
    expect(stateTone("registered_unmanaged")).toBe("warning");
    expect(stateTone("stale")).toBe("neutral");
    expect(severityTone("high")).toBe("critical");
    expect(severityTone("low")).toBe("warning");
    expect(runTone("partial")).toBe("warning");
    expect(runTone(null)).toBe("neutral");
  });

  it("lists sources newest first with the registry last", () => {
    expect(sourcesOf(entity()).map((s) => s.id)).toEqual(["c2", "c1", "registry"]);
  });

  it("suggests registry ids from discovered names", () => {
    expect(suggestAgentId("apps/crm-bot")).toBe("crm-bot");
    expect(suggestAgentId("openai/support/Support Bot")).toBe("bot");
    expect(suggestAgentId("i-0abc")).toBe("i-0abc");
    expect(suggestAgentId("///")).toBe("agent");
  });

  it("parses connector configuration safely", () => {
    expect(parseConfig("")).toEqual({ config: {} });
    expect(parseConfig('{"a": 1}').config).toEqual({ a: 1 });
    expect(parseConfig("[1]").error).toMatch(/JSON object/);
    expect(parseConfig("{nope").error).toMatch(/Not valid JSON/);
    for (const example of Object.values(CONNECTOR_EXAMPLES)) {
      expect(JSON.stringify(example)).not.toMatch(/sk-|token":\s*"[^D]/);
    }
  });
});

describe("inventory api", () => {
  it("talks to /inv/v1 with the admin key", async () => {
    const seen: { url: string; init?: RequestInit }[] = [];
    const api = new Api("cpk_test", async (url: string, init?: RequestInit) => {
      seen.push({ url, init });
      return new Response(JSON.stringify([]), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    await api.entities("acme", { agents_only: true, state: "shadow", q: "" });
    await api.linkEntity("acme", "e/1", "crm-bot");
    expect(seen[0]?.url).toBe("/inv/v1/tenants/acme/entities?agents_only=true&state=shadow");
    expect(seen[1]?.url).toBe("/inv/v1/tenants/acme/entities/e%2F1/link");
    expect(seen[1]?.init?.body).toBe(JSON.stringify({ agent_id: "crm-bot" }));
    expect((seen[1]?.init?.headers as Record<string, string>)["X-Admin-Key"]).toBe("cpk_test");
  });
});
