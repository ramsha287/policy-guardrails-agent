// Pure formatting helpers (unit-tested in tests/format.test.ts).

export function parseTime(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

/** "just now", "5 min ago", "3 h ago", "2 d ago"; future times read "in 4 min". */
export function relativeTime(iso: string | null | undefined, now: number = Date.now()): string {
  const t = parseTime(iso);
  if (t === null) return "—";
  const diff = Math.round((now - t) / 1000);
  const abs = Math.abs(diff);
  let text: string;
  if (abs < 45) return diff >= 0 ? "just now" : "in a few seconds";
  if (abs < 3600) text = `${Math.round(abs / 60)} min`;
  else if (abs < 86400) text = `${Math.round(abs / 3600)} h`;
  else text = `${Math.round(abs / 86400)} d`;
  return diff >= 0 ? `${text} ago` : `in ${text}`;
}

/** Remaining time as m:ss (or h:mm:ss), "expired" once past. */
export function countdown(expiresIso: string, now: number = Date.now()): string {
  const t = parseTime(expiresIso);
  if (t === null) return "—";
  let s = Math.floor((t - now) / 1000);
  if (s <= 0) return "expired";
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

/** Seconds left, clamped at 0. */
export function secondsLeft(expiresIso: string, now: number = Date.now()): number {
  const t = parseTime(expiresIso);
  return t === null ? 0 : Math.max(0, Math.floor((t - now) / 1000));
}

export function dateTime(iso: string | null | undefined): string {
  const t = parseTime(iso);
  if (t === null) return "—";
  return new Date(t).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** 1,284 / 12.9K / 4.2M */
export function compact(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  const abs = Math.abs(n);
  if (abs < 10_000) return Math.round(n).toLocaleString("en-US");
  if (abs < 1_000_000) return `${(n / 1000).toFixed(abs < 100_000 ? 1 : 0)}K`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

export function percent(fraction: number | null | undefined, digits = 1): string {
  if (fraction === null || fraction === undefined || Number.isNaN(fraction)) return "—";
  return `${(fraction * 100).toFixed(digits)}%`;
}

export function ms(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  if (value >= 1000) return `${(value / 1000).toFixed(2)} s`;
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ms`;
}

/** Nice round axis maximum and tick step for a count axis (0 / 5 / 10 …). */
export function niceScale(max: number, ticks = 4): { max: number; step: number } {
  if (!Number.isFinite(max) || max <= 0) return { max: 1, step: 1 };
  const rough = max / ticks;
  const mag = 10 ** Math.floor(Math.log10(rough));
  const norm = rough / mag;
  const nice = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10;
  let step = nice * mag;
  if (step < 1) step = 1; // counts are integers
  return { max: Math.ceil(max / step) * step, step };
}

export function shortId(id: string, n = 8): string {
  return id.length > n ? id.slice(0, n) : id;
}

export function scopeLabel(scopeType: string, scopeId: string | null): string {
  return scopeType === "global" ? "global" : `${scopeType}: ${scopeId ?? "?"}`;
}
