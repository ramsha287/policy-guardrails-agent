import { describe, expect, it } from "vitest";

import { compact, countdown, ms, niceScale, percent, relativeTime, scopeLabel, secondsLeft } from "../src/lib/format";

const NOW = Date.parse("2026-09-24T12:00:00Z");

describe("time", () => {
  it("relative time in both directions", () => {
    expect(relativeTime("2026-09-24T11:59:50Z", NOW)).toBe("just now");
    expect(relativeTime("2026-09-24T11:55:00Z", NOW)).toBe("5 min ago");
    expect(relativeTime("2026-09-24T09:00:00Z", NOW)).toBe("3 h ago");
    expect(relativeTime("2026-09-22T12:00:00Z", NOW)).toBe("2 d ago");
    expect(relativeTime("2026-09-24T12:04:00Z", NOW)).toBe("in 4 min");
    expect(relativeTime(null, NOW)).toBe("—");
    expect(relativeTime("not a date", NOW)).toBe("—");
  });

  it("countdown for review expiry", () => {
    expect(countdown("2026-09-24T12:04:32Z", NOW)).toBe("4:32");
    expect(countdown("2026-09-24T13:05:09Z", NOW)).toBe("1:05:09");
    expect(countdown("2026-09-24T11:59:59Z", NOW)).toBe("expired");
    expect(secondsLeft("2026-09-24T12:01:00Z", NOW)).toBe(60);
    expect(secondsLeft("2026-09-24T11:00:00Z", NOW)).toBe(0);
  });
});

describe("numbers", () => {
  it("compact counts", () => {
    expect(compact(1284)).toBe("1,284");
    expect(compact(12_900)).toBe("12.9K");
    expect(compact(250_000)).toBe("250K");
    expect(compact(4_200_000)).toBe("4.2M");
    expect(compact(null)).toBe("—");
  });

  it("percent and latency", () => {
    expect(percent(0.0612)).toBe("6.1%");
    expect(percent(undefined)).toBe("—");
    expect(ms(4.25)).toBe("4.3 ms");
    expect(ms(388)).toBe("388 ms");
    expect(ms(1520)).toBe("1.52 s");
  });

  it("nice axis scale uses round integer steps", () => {
    expect(niceScale(0)).toEqual({ max: 1, step: 1 });
    expect(niceScale(3)).toEqual({ max: 3, step: 1 });
    expect(niceScale(128)).toEqual({ max: 150, step: 50 });
    expect(niceScale(1900)).toEqual({ max: 2000, step: 500 });
  });

  it("scope labels", () => {
    expect(scopeLabel("global", null)).toBe("global");
    expect(scopeLabel("agent", "acme/bot")).toBe("agent: acme/bot");
  });
});
