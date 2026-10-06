import { describe, expect, it } from "vitest";

import { Api } from "../src/lib/api";
import { agreementRate, labelShare, normaliseClasses, pilotNote, sameClasses } from "../src/lib/advisors";
import type { AdvisorSummary } from "../src/lib/types";

function summary(over: Partial<AdvisorSummary> = {}): AdvisorSummary {
  return {
    advisor: "jev",
    provider: "http",
    mode: "shadow",
    questions: 100,
    by_status: { answered: 100 },
    by_label: { benign: 80, suspicious: 15, malicious: 5 },
    points: 0,
    verify_requests: 0,
    no_signal_rate: 0,
    agreement: { flagged_stopped: 18, flagged_released: 2, benign_stopped: 0, benign_released: 80 },
    ...over,
  };
}

describe("advisor pilot helpers", () => {
  it("reads label shares over answered questions", () => {
    expect(labelShare(summary(), "malicious")).toBeCloseTo(0.05);
    expect(labelShare(summary({ by_status: { answered: 0 }, by_label: {} }), "benign")).toBe(0);
  });

  it("computes agreement among flagged requests", () => {
    expect(agreementRate(summary())).toBeCloseTo(0.9);
    expect(agreementRate(summary({ agreement: { flagged_stopped: 0, flagged_released: 0, benign_stopped: 0, benign_released: 1 } }))).toBeNull();
  });

  it("flags advisors worth a human's attention", () => {
    expect(pilotNote(summary()).tone).toBe("warning"); // 2 released requests it flagged
    expect(pilotNote(summary({ agreement: { flagged_stopped: 20, flagged_released: 0, benign_stopped: 0, benign_released: 80 } })).tone).toBe("good");
    expect(pilotNote(summary({ no_signal_rate: 0.2 })).tone).toBe("warning");
    expect(pilotNote(summary({ by_status: { timeout: 100 }, by_label: {} })).tone).toBe("critical");
    expect(pilotNote(summary({ questions: 0, by_status: {}, by_label: {} })).tone).toBe("neutral");
  });

  it("normalises data classes to canonical order without unknowns", () => {
    expect(normaliseClasses(["PII", "PUBLIC", "PII", "SECRET"])).toEqual(["PUBLIC", "PII"]);
    expect(sameClasses(["INTERNAL", "PII"], ["PII", "INTERNAL"])).toBe(true);
    expect(sameClasses(undefined, [])).toBe(true);
    expect(sameClasses(["INTERNAL"], ["PII"])).toBe(false);
  });
});

describe("advisor api", () => {
  it("reads the pilot and writes the data policy", async () => {
    const seen: { url: string; init?: RequestInit }[] = [];
    const api = new Api("cpk_test", async (url: string, init?: RequestInit) => {
      seen.push({ url, init });
      return new Response(JSON.stringify({ advisors: [], rows: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    await api.advisorAnalytics({ tenant_id: "acme", hours: 168, environment: "" });
    await api.setAdvisorPolicy("acme", ["INTERNAL", "PII"]);
    expect(seen[0]?.url).toBe("/cp/v1/analytics/advisors?tenant_id=acme&hours=168");
    expect(seen[1]?.url).toBe("/cp/v1/tenants/acme/advisor-policy");
    expect(seen[1]?.init?.method).toBe("PUT");
    expect(seen[1]?.init?.body).toBe(JSON.stringify({ data_classes: ["INTERNAL", "PII"] }));
  });
});
