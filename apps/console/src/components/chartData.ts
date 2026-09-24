import { DECISIONS, type Decision } from "../lib/types";

export interface Bucket {
  start: number; // epoch ms
  counts: Record<Decision, number>;
  total: number;
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

function floorTo(t: number, unit: "hour" | "day"): number {
  const d = new Date(t);
  if (unit === "hour") d.setUTCMinutes(0, 0, 0);
  else d.setUTCHours(0, 0, 0, 0);
  return d.getTime();
}

/**
 * Dense buckets for the whole window (empty hours/days are zero, not missing), oldest first.
 * Points outside the window are ignored.
 */
export function buildBuckets(
  series: { bucket: string; decision: Decision; requests: number }[],
  hours: number,
  unit: "hour" | "day",
  now: number = Date.now(),
): Bucket[] {
  const step = unit === "hour" ? HOUR : DAY;
  const end = floorTo(now, unit);
  const count = Math.max(1, Math.ceil((hours * HOUR) / step));
  const start = end - (count - 1) * step;
  const buckets: Bucket[] = [];
  const index = new Map<number, Bucket>();
  for (let t = start; t <= end; t += step) {
    const b: Bucket = { start: t, counts: { allow: 0, modify: 0, escalate: 0, block: 0 }, total: 0 };
    buckets.push(b);
    index.set(t, b);
  }
  for (const p of series) {
    const t = Date.parse(p.bucket);
    if (Number.isNaN(t)) continue;
    const b = index.get(floorTo(t, unit));
    if (!b || !DECISIONS.includes(p.decision)) continue;
    b.counts[p.decision] += p.requests;
    b.total += p.requests;
  }
  return buckets;
}
