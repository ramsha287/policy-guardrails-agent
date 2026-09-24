// Gateways report a heartbeat every few seconds: installed guardrails, the snapshot and catalog they
// serve, and their last error. A gateway with no heartbeat for GATEWAY_STALE_SECONDS is not live.

import { Badge, Card, EmptyState, ErrorBanner, Loading, Mono, PageHeader } from "../components/ui";
import { relativeTime } from "../lib/format";
import { useNow, useResource } from "../lib/hooks";
import { useSession } from "../lib/session";
import { ENVIRONMENTS, type Environment, type Gateway, type Snapshot } from "../lib/types";

export function gatewayHealth(g: Gateway, liveVersion: string | null | undefined) {
  if (!g.live) return { tone: "critical" as const, label: "no heartbeat" };
  if (g.last_error) return { tone: "serious" as const, label: "error" };
  if (liveVersion && g.snapshot_version !== liveVersion) return { tone: "warning" as const, label: "behind" };
  return { tone: "good" as const, label: "healthy" };
}

export function FleetPage() {
  const { api } = useSession();
  const now = useNow(10_000);
  const data = useResource(
    async () => {
      const perEnv = await Promise.all(
        ENVIRONMENTS.map(async (env) => {
          const [gateways, current] = await Promise.all([
            api.gateways(env),
            api.currentSnapshot(env).catch(() => null as Snapshot | null),
          ]);
          return { env, gateways, current };
        }),
      );
      return perEnv;
    },
    [api],
    15_000,
  );
  return (
    <>
      <PageHeader
        title="Gateways"
        description="Every gateway's heartbeat: what it runs, whether it is on the live snapshot, and its last error."
      />
      <ErrorBanner error={data.error} />
      {data.data === undefined ? (
        <Loading />
      ) : (
        <div className="stack">
          {data.data.map(({ env, gateways, current }) => (
            <EnvFleet key={env} env={env} gateways={gateways} liveVersion={current?.version ?? null} now={now} />
          ))}
        </div>
      )}
    </>
  );
}

function EnvFleet({
  env,
  gateways,
  liveVersion,
  now,
}: {
  env: Environment;
  gateways: Gateway[];
  liveVersion: string | null;
  now: number;
}) {
  const live = gateways.filter((g) => g.live).length;
  return (
    <Card
      flush
      title={
        <span className="row">
          {env}
          <span className="muted">
            {live} of {gateways.length} live · snapshot <Mono>{liveVersion ?? "none"}</Mono>
          </span>
        </span>
      }
    >
      {gateways.length === 0 ? (
        <EmptyState title="No gateway has reported yet" />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Gateway</th>
                <th scope="col">Health</th>
                <th scope="col">Snapshot</th>
                <th scope="col">Catalog</th>
                <th scope="col">Installed guardrails</th>
              </tr>
            </thead>
            <tbody>
              {gateways.map((g) => {
                const h = gatewayHealth(g, liveVersion);
                return (
                  <tr key={g.gateway_id}>
                    <td>
                      <Mono>{g.gateway_id}</Mono>
                      <span className="cell-sub">seen {relativeTime(g.last_seen, now)}</span>
                    </td>
                    <td>
                      <Badge tone={h.tone}>{h.label}</Badge>
                      {g.last_error && <span className="cell-sub">{g.last_error}</span>}
                    </td>
                    <td>
                      <Mono>{g.snapshot_version ?? "none"}</Mono>
                    </td>
                    <td>
                      <Mono>{g.catalog_version ?? "none"}</Mono>
                    </td>
                    <td>
                      {g.installed.map((i) => (
                        <span key={i} className="tag">
                          {i}
                        </span>
                      ))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
