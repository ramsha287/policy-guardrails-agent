import { describe, expect, it } from "vitest";

import { buildBuckets } from "../src/components/chartData";
import { parseHash, buildHash } from "../src/lib/router";
import type { Assignment, Gateway } from "../src/lib/types";
import { diffAssignments } from "../src/pages/Approvals";
import { keyState, rateLabel } from "../src/pages/Catalog";
import { gatewayHealth } from "../src/pages/Fleet";
import { riskTone } from "../src/pages/Reviews";
import { buildPayload } from "../src/pages/Simulate";

const A = (over: Partial<Assignment>): Assignment => ({
  id: "a",
  guardrail_id: "g",
  guardrail_version: "1.0.0",
  scope_type: "global",
  scope_id: null,
  stages: ["input"],
  order: 100,
  parallel_group: null,
  enabled: true,
  mode: "shadow",
  failure_mode: null,
  timeout_ms: null,
  config: {},
  ...over,
});

describe("router", () => {
  it("parses and builds hashes", () => {
    expect(parseHash("#/reviews?id=abc&status=all")).toEqual({ path: "/reviews", query: { id: "abc", status: "all" } });
    expect(parseHash("")).toEqual({ path: "/", query: {} });
    expect(parseHash("#/pipeline/")).toEqual({ path: "/pipeline", query: {} });
    expect(buildHash("/pipeline", { env: "production", id: null })).toBe("#/pipeline?env=production");
  });
});

describe("chart buckets", () => {
  it("fills the window densely and ignores points outside it", () => {
    const now = Date.parse("2026-09-24T12:30:00Z");
    const b = buildBuckets(
      [
        { bucket: "2026-09-24T12:00:00+00:00", decision: "allow", requests: 5 },
        { bucket: "2026-09-24T12:00:00+00:00", decision: "block", requests: 2 },
        { bucket: "2026-09-24T10:00:00+00:00", decision: "modify", requests: 1 },
        { bucket: "2026-09-20T10:00:00+00:00", decision: "allow", requests: 99 },
      ],
      24,
      "hour",
      now,
    );
    expect(b).toHaveLength(24);
    const last = b[b.length - 1]!;
    expect(last.total).toBe(7);
    expect(last.counts.block).toBe(2);
    expect(b.reduce((s, x) => s + x.total, 0)).toBe(8);
  });

  it("uses day buckets for long windows", () => {
    const b = buildBuckets([], 24 * 30, "day", Date.parse("2026-09-24T12:00:00Z"));
    expect(b).toHaveLength(30);
  });
});

describe("diffs", () => {
  it("finds added, removed and changed assignments", () => {
    const d = diffAssignments(
      [A({ id: "keep" }), A({ id: "gone" }), A({ id: "edit", mode: "shadow" })],
      [A({ id: "keep" }), A({ id: "edit", mode: "enforce" }), A({ id: "new" })],
    );
    expect(d.map((x) => [x.id, x.kind])).toEqual([
      ["edit", "changed"],
      ["gone", "removed"],
      ["new", "added"],
    ]);
  });
});

describe("status helpers", () => {
  it("api key state", () => {
    const base = { id: "k", tenant_id: "t", name: "n", prefix: "gk_", scopes: [], environments: null, created_at: "", revoked_at: null };
    expect(keyState({ ...base, is_active: true, expires_at: null }).label).toBe("active");
    expect(keyState({ ...base, is_active: false, expires_at: null }).label).toBe("revoked");
    expect(keyState({ ...base, is_active: true, expires_at: "2020-01-01T00:00:00Z" }).label).toBe("expired");
  });

  it("rate limit labels", () => {
    expect(rateLabel(null)).toBe("default");
    expect(rateLabel(undefined)).toBe("default");
    expect(rateLabel(0)).toBe("unlimited");
    expect(rateLabel(120)).toBe("120/min");
  });

  it("gateway health", () => {
    const g: Gateway = { gateway_id: "g", environment: "dev", snapshot_version: "v2", catalog_version: "c", last_error: null, installed: [], last_seen: "", live: true };
    expect(gatewayHealth(g, "v2").label).toBe("healthy");
    expect(gatewayHealth(g, "v3").label).toBe("behind");
    expect(gatewayHealth({ ...g, last_error: "boom" }, "v2").label).toBe("error");
    expect(gatewayHealth({ ...g, live: false }, "v2").label).toBe("no heartbeat");
  });

  it("risk tone thresholds", () => {
    expect(riskTone(90)).toBe("critical");
    expect(riskTone(65)).toBe("serious");
    expect(riskTone(45)).toBe("warning");
    expect(riskTone(10)).toBe("neutral");
  });
});

describe("simulate payloads", () => {
  it("per stage", () => {
    expect(buildPayload("input", "hi", "", "")).toEqual({ text: "hi" });
    expect(buildPayload("retrieval", "a\n\n b ", "", "")).toEqual({ chunks: [{ id: "c1", text: "a" }, { id: "c2", text: "b" }] });
    expect(buildPayload("tool", "", "http.post", '{"url": "x"}')).toEqual({ tool_call: { name: "http.post", arguments: { url: "x" } } });
    expect(() => buildPayload("tool", "", "t", "[1]")).toThrow();
    expect(() => buildPayload("tool", "", "t", "{bad")).toThrow();
  });
});
