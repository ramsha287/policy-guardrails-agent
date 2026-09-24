// Minimal hash router: #/reviews?id=abc  ->  { path: "/reviews", query: { id: "abc" } }.
// Hash routing keeps the console a set of static files the control plane can serve as-is.

import { useCallback, useEffect, useState } from "react";

export interface Route {
  path: string;
  query: Record<string, string>;
}

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#/, "") || "/";
  const [pathPart, queryPart = ""] = raw.split("?", 2) as [string, string?];
  const path = `/${pathPart.replace(/^\/+|\/+$/g, "")}`;
  const query: Record<string, string> = {};
  new URLSearchParams(queryPart).forEach((v, k) => {
    query[k] = v;
  });
  return { path, query };
}

export function buildHash(path: string, query: Record<string, string | undefined | null> = {}): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v) q.set(k, v);
  const s = q.toString();
  return `#${path}${s ? `?${s}` : ""}`;
}

export function navigate(path: string, query: Record<string, string | undefined | null> = {}): void {
  const next = buildHash(path, query);
  if (window.location.hash !== next) window.location.hash = next;
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

/** Read/write one query parameter of the current route. */
export function useQueryParam(route: Route, name: string): [string, (value: string | null) => void] {
  const value = route.query[name] ?? "";
  const set = useCallback(
    (v: string | null) => navigate(route.path, { ...route.query, [name]: v ?? undefined }),
    [route, name],
  );
  return [value, set];
}
