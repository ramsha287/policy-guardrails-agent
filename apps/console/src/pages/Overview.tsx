// What needs attention right now: held requests, publishes waiting for approval, unhealthy gateways,
// and the last 24 hours of decisions.

import { DecisionChart } from "../components/DecisionChart";
import { Badge, Card, EmptyState, ErrorBanner, Loading, Mono, PageHeader } from "../components/ui";
import { relativeTime } from "../lib/format";
import { useNow, useResource } from "../lib/hooks";
import { useSession } from "../lib/session";
import { ENVIRONMENTS, type Diff, type Gateway, type Snapshot } from "../lib/types";
import { AnalyticsTiles } from "./Analytics";
import { gatewayHealth } from "./Fleet";

export function OverviewPage() {
  const { api, me } = useSession();
  const now = useNow(30_000);
  const reviews = useResource(() => api.reviews({ status: "pending" }), [api], 10_000);
  const requests = useResource(
    () => (me.platform ? api.publishRequests({ status: "pending" }) : Promise.resolve([])),
    [api],
    30_000,
  );
  const envs = useResource(
    () =>
      Promise.all(
        ENVIRONMENTS.map(async (env) => {
          const [current, gateways, diff] = await Promise.all([
            api.currentSnapshot(env).catch(() => null as Snapshot | null),
            api.gateways(env).catch(() => [] as Gateway[]),
            api.diff(env).catch(() => null as Diff | null),
          ]);
          return { env, current, gateways, diff };
        }),
      ),
    [api],
    30_000,
  );
  const analytics = useResource(
    () => (me.features.analytics ? api.analytics({ hours: 24 }) : Promise.resolve(undefined)),
    [api],
    60_000,
  );
  const changes = useResource(() => (me.platform ? api.changes({ limit: 8 }) : Promise.resolve([])), [api], 60_000);

  const pendingReviews = reviews.data?.length ?? 0;
  const soonest = [...(reviews.data ?? [])].sort((a, b) => a.expires_at.localeCompare(b.expires_at))[0];
  const allGateways = (envs.data ?? []).flatMap((e) => e.gateways.map((g) => ({ g, live: e.current?.version ?? null })));
  const unhealthy = allGateways.filter(({ g, live }) => gatewayHealth(g, live).tone !== "good");

  return (
    <>
      <PageHeader
        title="Overview"
        description={`Signed in as ${me.name}${me.tenant_id ? ` for tenant ${me.tenant_id}` : ""}.`}
      />
      <ErrorBanner error={reviews.error ?? envs.error} />
      <div className="grid-stats">
        <a className="stat stat-link" href="#/reviews">
          <span className="stat-label">Waiting for review</span>
          <span className="stat-value">{reviews.data ? pendingReviews : "—"}</span>
          <span className="stat-hint">
            {soonest ? `next expires ${relativeTime(soonest.expires_at, now)}` : "queue is empty"}
          </span>
        </a>
        {me.platform && (
          <a className="stat stat-link" href="#/approvals">
            <span className="stat-label">Publishes to approve</span>
            <span className="stat-value">{requests.data ? requests.data.length : "—"}</span>
            <span className="stat-hint">two-person rule: {me.two_person_environments.join(", ") || "off"}</span>
          </a>
        )}
        <a className="stat stat-link" href="#/fleet">
          <span className="stat-label">Gateways</span>
          <span className="stat-value">
            {envs.data ? `${allGateways.filter(({ g }) => g.live).length}/${allGateways.length}` : "—"}
          </span>
          <span className="stat-hint">
            {envs.data === undefined ? (
              "…"
            ) : unhealthy.length === 0 ? (
              <Badge tone="good">all healthy</Badge>
            ) : (
              <Badge tone="serious">{`${unhealthy.length} need attention`}</Badge>
            )}
          </span>
        </a>
      </div>

      <Card flush title="Environments">
        {envs.data === undefined ? (
          <Loading />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Environment</th>
                  <th scope="col">Live snapshot</th>
                  <th scope="col">Unpublished changes</th>
                  <th scope="col">Gateways</th>
                </tr>
              </thead>
              <tbody>
                {envs.data.map(({ env, current, gateways, diff }) => {
                  const pending = diff ? diff.added.length + diff.changed.length + diff.removed.length : 0;
                  const live = gateways.filter((g) => g.live);
                  const behind = live.filter((g) => current && g.snapshot_version !== current.version).length;
                  return (
                    <tr key={env}>
                      <td>
                        <a href={`#/pipeline?env=${env}`}>{env}</a>
                      </td>
                      <td>
                        {current ? (
                          <>
                            <Mono>{current.version}</Mono>
                            <span className="cell-sub">
                              {current.published_by}, {relativeTime(current.published_at, now)}
                            </span>
                          </>
                        ) : (
                          <span className="muted">nothing published</span>
                        )}
                      </td>
                      <td>{pending > 0 ? <Badge tone="warning">{`${pending} pending`}</Badge> : <span className="muted">none</span>}</td>
                      <td>
                        {live.length} live
                        {behind > 0 && <span className="cell-sub">{behind} not on the live snapshot yet</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {me.features.analytics && (
        <Card title="Last 24 hours">
          <ErrorBanner error={analytics.error} />
          {analytics.data === undefined ? (
            analytics.error ? null : <Loading />
          ) : (
            <>
              <AnalyticsTiles data={analytics.data} />
              {analytics.data.summary.requests === 0 ? (
                <EmptyState title="No traffic in the last 24 hours" />
              ) : (
                <DecisionChart series={analytics.data.timeseries} hours={24} unit="hour" />
              )}
            </>
          )}
        </Card>
      )}

      {me.platform && (
        <Card flush title="Recent changes" actions={<a href="#/activity">All activity</a>}>
          {changes.data === undefined ? (
            <Loading />
          ) : changes.data.length === 0 ? (
            <EmptyState title="No changes yet" />
          ) : (
            <table className="table table-compact">
              <tbody>
                {changes.data.map((c) => (
                  <tr key={`${c.id}-${c.at}`}>
                    <td>
                      <strong>{c.action}</strong> {c.entity} <Mono>{c.entity_id}</Mono>
                    </td>
                    <td>{c.actor}</td>
                    <td className="num muted">{relativeTime(c.at, now)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </>
  );
}
