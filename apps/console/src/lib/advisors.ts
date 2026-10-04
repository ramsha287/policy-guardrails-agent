// Advisor pilot helpers: reading an advisor's shadow record and the tenant data policy.

import type { AdvisorSummary, DataClass } from "./types";
import { DATA_CLASSES } from "./types";

export type Tone = "good" | "warning" | "critical" | "neutral";

/** More than this share of questions without an answer (timeouts, errors, invalid) needs a look. */
export const NO_SIGNAL_LIMIT = 0.05;

export function answered(a: AdvisorSummary): number {
  return a.by_status.answered ?? 0;
}

/** Share of answered questions with this label (0 when nothing was answered). */
export function labelShare(a: AdvisorSummary, label: string): number {
  const n = answered(a);
  return n ? (a.by_label[label] ?? 0) / n : 0;
}

/** Requests the advisor flagged that the deterministic path stopped too, among all it flagged. */
export function agreementRate(a: AdvisorSummary): number | null {
  const flagged = a.agreement.flagged_stopped + a.agreement.flagged_released;
  return flagged ? a.agreement.flagged_stopped / flagged : null;
}

/** One line on what the pilot shows so far, for the advisors table. */
export function pilotNote(a: AdvisorSummary): { tone: Tone; text: string } {
  if (a.questions === 0) return { tone: "neutral", text: "no questions yet" };
  if (answered(a) === 0) return { tone: "critical", text: "never answered (check the endpoint and timeout)" };
  if (a.no_signal_rate > NO_SIGNAL_LIMIT) {
    return { tone: "warning", text: `${Math.round(a.no_signal_rate * 100)}% without an answer` };
  }
  const extra = a.agreement.flagged_released;
  if (extra > 0) {
    return { tone: "warning", text: `${extra} released request${extra === 1 ? "" : "s"} flagged: review before enforcing` };
  }
  return { tone: "good", text: "agrees with the deterministic path" };
}

/** Classes in canonical order, without duplicates or unknown values. */
export function normaliseClasses(classes: readonly string[]): DataClass[] {
  return DATA_CLASSES.filter((c) => classes.includes(c));
}

export function sameClasses(a: readonly string[] | undefined, b: readonly string[]): boolean {
  const x = normaliseClasses(a ?? []);
  const y = normaliseClasses(b);
  return x.length === y.length && x.every((c, i) => c === y[i]);
}
