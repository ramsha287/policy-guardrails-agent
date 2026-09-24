import { useCallback, useEffect, useRef, useState } from "react";

export interface Resource<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  reload: () => Promise<void>;
}

/**
 * Loads data and keeps the last good result while reloading (no flash, no layout jump).
 * `pollMs` refreshes in the background while the tab is visible.
 */
export function useResource<T>(load: () => Promise<T>, deps: unknown[], pollMs?: number): Resource<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<Error>();
  const [loading, setLoading] = useState(true);
  const loadRef = useRef(load);
  loadRef.current = load;
  const seq = useRef(0);

  const reload = useCallback(async () => {
    const mine = ++seq.current;
    setLoading(true);
    try {
      const result = await loadRef.current();
      if (mine === seq.current) {
        setData(result);
        setError(undefined);
      }
    } catch (e) {
      if (mine === seq.current) setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      if (mine === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    setData(undefined);
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    if (!pollMs) return;
    const id = window.setInterval(() => {
      if (!document.hidden) void reload();
    }, pollMs);
    return () => window.clearInterval(id);
  }, [pollMs, reload]);

  return { data, error, loading, reload };
}

/** Current time, re-rendering every `intervalMs` (for countdowns and "5 min ago"). */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}

/** Runs an async action with a busy flag and a captured error, for buttons and forms. */
export function useAction<A extends unknown[], R>(fn: (...args: A) => Promise<R>) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error>();
  const run = useCallback(
    async (...args: A): Promise<R | undefined> => {
      setBusy(true);
      setError(undefined);
      try {
        return await fn(...args);
      } catch (e) {
        setError(e instanceof Error ? e : new Error(String(e)));
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [fn],
  );
  return { run, busy, error, clearError: () => setError(undefined) };
}
