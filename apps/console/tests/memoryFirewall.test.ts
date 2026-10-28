import { describe, expect, it } from "vitest";

import { Api } from "../src/lib/api";
import {
  blankItem,
  eventTone,
  SAMPLE_ITEMS,
  scanLabel,
  selfTestMatrix,
  serviceHealth,
  trimItems,
  uptime,
  validateItems,
  verdictView,
} from "../src/lib/memoryFirewall";
import type { MemoryVerdict, SelfTestResult } from "../src/lib/types";

const verdict = (over: Partial<MemoryVerdict> = {}): MemoryVerdict => ({
  id: "a",
  source: "user",
  writer: "w",
  admitted: true,
  quarantine_reason: null,
  scan_findings: [],
  signature: "ab",
  ...over,
});

describe("memory firewall: service health", () => {
  it("names every state", () => {
    expect(serviceHealth(undefined).label).toBe("checking");
    expect(serviceHealth({ configured: false, reachable: false, ready: false })).toEqual({ tone: "neutral", label: "not configured" });
    expect(serviceHealth({ configured: true, reachable: false, ready: false, error: "x" }).tone).toBe("critical");
    expect(serviceHealth({ configured: true, reachable: true, ready: false }).label).toBe("not ready");
    expect(serviceHealth({ configured: true, reachable: true, ready: true, error: "refused" }).label).toBe("error");
  });
});

describe("memory firewall: memory items", () => {
  it("ships an example with every outcome", () => {
    expect(SAMPLE_ITEMS.map((i) => i.source)).toContain("web");
    expect(SAMPLE_ITEMS.some((i) => !i.authorized)).toBe(true);
    expect(validateItems(SAMPLE_ITEMS)).toEqual([]);
  });

  it("validates like the control plane", () => {
    expect(validateItems([])).toEqual(["Add at least one memory item."]);
    const errors = validateItems([
      { id: "x", text: "", source: "user", writer: "", authorized: true },
      { id: "x", text: "a".repeat(32_769), source: "user", writer: "w", authorized: true },
      { id: " ", text: "", source: "user", writer: "w", authorized: true },
    ]);
    expect(errors).toEqual([
      "x: a writer is required.",
      "x: the id is used twice.",
      "x: text is longer than 32768 characters.",
      "Item 3: an id is required.",
    ]);
  });

  it("adds items with unique ids and trims fields", () => {
    const next = blankItem([{ ...SAMPLE_ITEMS[0]!, id: "memory-2" }]);
    expect(next.id).toBe("memory-3");
    expect(trimItems([{ id: " a ", text: " keep ", source: "user ", writer: " w", authorized: true }])[0]).toEqual({
      id: "a",
      text: " keep ",
      source: "user",
      writer: "w",
      authorized: true,
    });
  });
});

describe("memory firewall: verdicts and the self-test", () => {
  it("maps verdicts to labels", () => {
    expect(verdictView(verdict()).label).toBe("admitted");
    expect(verdictView(verdict({ scan_findings: ["injection-text: ignore"] })).tone).toBe("warning");
    expect(verdictView(verdict({ admitted: false, quarantine_reason: "unauthorized writer" }))).toEqual({
      tone: "critical",
      label: "quarantined",
      detail: "unauthorized writer",
    });
    expect(scanLabel("injection-text: ignore\\s+(all")).toBe("injection-text · ignore\\s+(all");
    expect(scanLabel("odd")).toBe("odd");
  });

  it("pivots the self-test into attack x mode", () => {
    const r: SelfTestResult = {
      modes: ["plain", "guard"],
      results: [
        { attack: "Edit content", mode: "plain", control: "reject", tampered: "approve", result: "SUCCEEDED" },
        { attack: "Edit content", mode: "guard", control: "reject", tampered: "error", result: "DETECTED" },
        { attack: "Replay old state", mode: "guard", control: "reject", tampered: "error", result: "DETECTED" },
      ],
      attacks: 2,
      guard_blocked: 2,
      passed: true,
      finished_at: "2026-10-28T00:00:00Z",
      duration_ms: 900,
    };
    expect(selfTestMatrix(r)).toEqual([
      { attack: "Edit content", cells: { plain: "SUCCEEDED", guard: "DETECTED" } },
      { attack: "Replay old state", cells: { guard: "DETECTED" } },
    ]);
  });

  it("formats uptime and event tones", () => {
    expect(uptime(42)).toBe("42 s");
    expect(uptime(3 * 3600 + 120)).toBe("3 h 2 min");
    expect(uptime(5 * 86400)).toBe("5 days");
    expect(eventTone("quarantine")).toBe("critical");
    expect(eventTone("write")).toBe("good");
  });
});

describe("memory firewall: API client", () => {
  it("calls the control plane's relay with the admin key", async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const api = new Api("cpk_x", async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({ results: [], summary: {}, key_id: "k", events: [] }), { status: 200 });
    });
    await api.memoryFirewallInspect([SAMPLE_ITEMS[0]!], false);
    await api.memoryFirewallEvents(10);
    expect(calls[0]!.url).toBe("/cp/v1/memory-firewall/inspect");
    expect(JSON.parse(String(calls[0]!.init?.body))).toEqual({ items: [SAMPLE_ITEMS[0]], scan: false });
    expect((calls[0]!.init?.headers as Record<string, string>)["X-Admin-Key"]).toBe("cpk_x");
    expect(calls[1]!.url).toBe("/cp/v1/memory-firewall/events?limit=10");
  });
});
