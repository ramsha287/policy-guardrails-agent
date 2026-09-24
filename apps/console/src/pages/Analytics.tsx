// Decisions and latency from the gateways' audit log. Filters sit in one row above everything they
// scope; reloads keep the previous render (no flash).

import { useMemo } from "react";

import { DecisionChart } from "../components/DecisionChart";
import {
  Badge,
  Card,
  DecisionBadge,
  EmptyState,
  ErrorBanner,
  Loading,
  ModeBadge,
  PageHeader,
  Segmented,
  Toolbar,
} from "../components/ui";
import { compact, ms, percent } from "../lib/format";
import { useResource } from "../lib/hooks";
import { useQueryParam, useRoute } from "../lib/router";
import { useSession } from "../lib/session";
import { DECISIONS, ENVIRONMENTS, type Analytics, type Environment } from "../lib/types";

export const LATENCY_SLO_MS = 500; // plan: total guardrail overhead <= 500 ms p95 per agent turn

const RANGES = [
  { value: "24", label: "24 hours" },
  { value: "168", label: "7 days" },
  { value: "720", label: "30 days" },
  { value: "2160", label: "90 days" },
];

export function slowestStageP95(a: Analytics): number | null {
  const values = a.totals.map((t) => t.p95_latency_ms).filter((v): v is number => v !== null);
  return values.length ? Math.max(...values) : null;
}

export function AnalyticsTiles({ data }: { data: Analytics }) {
  const p95 = slowestStageP95(data);
  const ratio = p95 === null ? 0 : p95 / LATENCY_SLO_MS;
  const meter = ratio > 1 ? "meter meter-critical" : ratio > 0.8 ? "meter meter-warning" : "meter";
  const blocked = data.summary.by_decision.block ?? 0;
  return (
    <div className="grid-stats">
      <div className="stat stat-hero">
        <span className="stat-label">Requests</span>
        <span className="stat-value">{compact(data.summary.requests)}</span>
        <span className="stat-hint">
          last {data.hours >= 48 ? `${Math.round(data.hours / 24)} days` : `${data.hours} hours`}
        </span>
      </div>
      <div className="stat">
        <span className="stat-label">Blocked</span>
        <span className="stat-value">{percent(data.summary.block_rate)}</span>
        <span className="stat-hint">
          {compact(blocked)} requests · {compact(data.summary.policy_denied)} by policy
        </span>
      </div>
      <div className="stat">
        <span className="stat-label">Modified</span>
        <span className="stat-value">
          {percent(data.summary.requests ? (data.summary.by_decision.modify ?? 0) / data.summary.requests : null)}
        </span>
        <span className="stat-hint">{compact(data.summary.by_decision.modify ?? 0)} redacted or rewritten</span>
      </div>
      <div className="stat">
        <span className="stat-label">Slowest stage p95</span>
        <span className="stat-value">{ms(p95)}</span>
        <div className={meter} role="meter" aria-valuemin={0} aria-valuemax={LATENCY_SLO_MS} aria-valuenow={p95 ?? 0} aria-label="p95 latency against the 500 ms budget">
          <span style={{ width: `${Math.min(100, ratio * 100)}%` }} />
        </div>
        <span className="stat-hint">
          {p95 === null ? (
            "no traffic"
          ) : ratio > 1 ? (
            <Badge tone="critical">over the {LATENCY_SLO_MS} ms budget</Badge>
          ) : (
            `budget ${LATENCY_SLO_MS} ms per turn`
          )}
        </span>
      </div>
    </div>
  );
}

export function AnalyticsPage() {
  const { api, me } = useSession();
  const route = useRoute();
  const [hoursParam, setHours] = useQueryParam(route, "hours");
  const [envParam, setEnv] = useQueryParam(route, "env");
  const [tenantParam, setTenant] = useQueryParam(route, "tenant");
  const hours = Number(hoursParam || "24");
  const env = (ENVIRONMENTS.includes(envParam as Environment) ? envParam : "") as Environment | "";
  const data = useResource(
    () => api.analytics({ hours, environment: env, tenant_id: tenantParam || undefined }),
    [api, hours, env, tenantParam],
    60_000,
  );
  const tenants = useResource(() => (me.platform ? api.tenants() : Promise.resolve([])), [api]);

  const byGuardrail = useMemo(() => {
    const groups = new Map<string, Analytics["rows"]>();
    for (const r of data.data?.rows ?? []) {
      const k = `${r.guardrail_id}@${r.version}`;
      groups.set(k, [...(groups.get(k) ?? []), r]);
    }
    return [...groups.entries()];
  }, [data.data]);

  return (
    <>
      <PageHeader title="Analytics" description="Decisions and latency from the audit log, across every gateway." />
      <Toolbar>
        <Segmented label="Time range" value={String(hours)} onChange={(v) => setHours(v === "24" ? null : v)} options={RANGES} />
        <select className="select select-auto" aria-label="Environment" value={env} onChange={(e) => setEnv(e.target.value || null)}>
          <option value="">All environments</option>
          {ENVIRONMENTS.map((e) => (
            <option key={e}>{e}</option>
          ))}
        </select>
        {me.platform && (
          <select
            className="select select-auto"
            aria-label="Tenant"
            value={tenantParam}
            onChange={(e) => setTenant(e.target.value || null)}
          >
            <option value="">All tenants</option>
            {(tenants.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.id}
              </option>
            ))}
          </select>
        )}
      </Toolbar>
      <ErrorBanner error={data.error} />
      {data.data === undefined ? (
        data.error ? null : <Loading />
      ) : (
        <div className={data.loading ? "stack refetching" : "stack"}>
          <AnalyticsTiles data={data.data} />
          <Card title="Requests by decision">
            {data.data.summary.requests === 0 ? (
              <EmptyState title="No traffic in this window" />
            ) : (
              <DecisionChart series={data.data.timeseries} hours={data.data.hours} unit={data.data.bucket} />
            )}
          </Card>
          <div className="stack">
            <Card flush title="By stage">
              {data.data.totals.length === 0 ? (
                <EmptyState title="No traffic" />
              ) : (
                <div className="table-wrap">
                  <table className="table table-compact">
                    <thead>
                      <tr>
                        <th scope="col">Stage</th>
                        <th scope="col">Decision</th>
                        <th scope="col" className="num">
                          Requests
                        </th>
                        <th scope="col" className="num">
                          Avg
                        </th>
                        <th scope="col" className="num">
                          p95
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.data.totals.map((t) => (
                        <tr key={`${t.stage}-${t.decision}`}>
                          <td>{t.stage}</td>
                          <td>
                            <DecisionBadge decision={t.decision} />
                          </td>
                          <td className="num">{compact(t.requests)}</td>
                          <td className="num">{ms(t.avg_latency_ms)}</td>
                          <td className="num">{ms(t.p95_latency_ms)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
            <Card flush title="By guardrail">
              {byGuardrail.length === 0 ? (
                <EmptyState title="No guardrail ran in this window" />
              ) : (
                <div className="table-wrap">
                  <table className="table table-compact">
                    <thead>
                      <tr>
                        <th scope="col">Guardrail</th>
                        <th scope="col">Mode</th>
                        {DECISIONS.map((d) => (
                          <th key={d} scope="col" className="num">
                            {d}
                          </th>
                        ))}
                        <th scope="col" className="num">
                          p95
                        </th>
                        <th scope="col" className="num">
                          Errors
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {byGuardrail.flatMap(([key, rows]) =>
                        (["enforce", "shadow"] as const)
                          .map((mode) => ({ mode, rows: rows.filter((r) => r.mode === mode) }))
                          .filter((g) => g.rows.length > 0)
                          .map(({ mode, rows: mr }) => {
                            const count = (d: string) => mr.filter((r) => r.decision === d).reduce((s, r) => s + r.n, 0);
                            const p95 = Math.max(...mr.map((r) => r.p95_latency_ms ?? 0));
                            const errors = mr.reduce((s, r) => s + r.errors, 0);
                            return (
                              <tr key={`${key}-${mode}`}>
                                <td>{key}</td>
                                <td>
                                  <ModeBadge mode={mode} />
                                </td>
                                {DECISIONS.map((d) => (
                                  <td key={d} className="num">
                                    {compact(count(d))}
                                  </td>
                                ))}
                                <td className="num">{ms(p95)}</td>
                                <td className="num">{errors > 0 ? <Badge tone="serious">{errors}</Badge> : 0}</td>
                              </tr>
                            );
                          }),
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </div>
        </div>
      )}
    </>
  );
}
