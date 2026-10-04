// Discovery connectors: the read-only sources the inventory is built from. Platform admins add and
// configure them (credentials are environment-variable NAMES on the control plane, never values);
// tenant editors can run one now.

import { useState } from "react";

import { IconPlus, IconRefresh } from "../components/icons";
import { TenantPicker, useTenantChoice } from "../components/TenantPicker";
import { useToast } from "../components/toast";
import {
  Badge,
  Button,
  Card,
  Dialog,
  EmptyState,
  ErrorBanner,
  Field,
  Loading,
  Mono,
  Notice,
  PageHeader,
} from "../components/ui";
import { dateTime, relativeTime } from "../lib/format";
import { useAction, useNow, useResource } from "../lib/hooks";
import { CONNECTOR_EXAMPLES, parseConfig, runTone } from "../lib/inventory";
import { useSession } from "../lib/session";
import { ENVIRONMENTS, type Connector, type ConnectorKind, type Environment, type SyncRun } from "../lib/types";

export function ConnectorsPage() {
  const { api, me, can } = useSession();
  const toast = useToast();
  const now = useNow(15_000);
  const { tenants, tenant, setTenant, error: tenantsError } = useTenantChoice();
  const tid = tenant?.id ?? "";
  const kinds = useResource(() => api.connectorKinds(), [api]);
  const connectors = useResource(() => (tid ? api.connectors(tid) : Promise.resolve([] as Connector[])), [api, tid], 15_000);
  const [editing, setEditing] = useState<Connector | "new" | null>(null);
  const [runsOf, setRunsOf] = useState<Connector | null>(null);
  const manage = me.platform && can("discovery:write");

  const sync = useAction(async (c: Connector) => {
    const run = await api.syncConnector(tid, c.id);
    const summary = `${run.observations} observations, ${run.entities_created} new, ${run.findings_opened} findings`;
    if (run.status === "ok") toast("good", `${c.name}: ${summary}.`);
    else if (run.status === "partial") toast("good", `${c.name} finished with warnings: ${summary}.`);
    else toast("critical", `${c.name} failed: ${run.error ?? "see its runs"}`);
    await connectors.reload();
  });
  const remove = useAction(async (c: Connector) => {
    if (!window.confirm(`Delete ${c.name}? Its evidence stays in the inventory; its relations stop being current.`)) return;
    await api.deleteConnector(tid, c.id);
    toast("good", `${c.name} deleted.`);
    await connectors.reload();
  });
  const kindOf = (k: string) => kinds.data?.find((x) => x.kind === k);

  return (
    <>
      <PageHeader
        title="Discovery connectors"
        description="Read-only sources the agent inventory is built from. Each runs on its interval; one run at a time."
        actions={
          <div className="row">
            <TenantPicker tenants={tenants} tenant={tenant} onChange={setTenant} />
            {manage && tid && (
              <Button icon={<IconPlus size={14} />} onClick={() => setEditing("new")}>
                New connector
              </Button>
            )}
          </div>
        }
      />
      <ErrorBanner error={tenantsError ?? connectors.error ?? kinds.error ?? sync.error ?? remove.error} />
      {tenants === undefined || connectors.data === undefined ? (
        <Loading />
      ) : !tenant ? (
        <Card>
          <EmptyState title="No tenants yet" />
        </Card>
      ) : connectors.data.length === 0 ? (
        <Card>
          <EmptyState title="No connectors for this tenant">
            {manage
              ? "Start with the gateway connector (agents calling through your gateways), then add Kubernetes or DNS logs to find the ones that don't."
              : "A platform admin adds connectors. Registered agents still show in the inventory."}
          </EmptyState>
        </Card>
      ) : (
        <Card flush>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Connector</th>
                  <th scope="col">Covers</th>
                  <th scope="col">Last run</th>
                  <th scope="col">Schedule</th>
                  <th scope="col" />
                </tr>
              </thead>
              <tbody>
                {connectors.data.map((c) => (
                  <tr key={c.id}>
                    <td>
                      {c.name}
                      <span className="cell-sub">{kindOf(c.kind)?.title ?? c.kind}</span>
                    </td>
                    <td>{c.environment ?? <span className="muted">any</span>}</td>
                    <td>
                      {c.last_status ? <Badge tone={runTone(c.last_status)}>{c.last_status}</Badge> : <span className="muted">never</span>}
                      {c.last_run_at && <span className="cell-sub">{relativeTime(c.last_run_at, now)}</span>}
                      {c.last_error && <span className="cell-sub">{c.last_error}</span>}
                    </td>
                    <td>
                      {c.enabled ? `every ${c.interval_minutes} min` : <Badge tone="neutral">paused</Badge>}
                      {c.lease_until && Date.parse(c.lease_until) > now && <span className="cell-sub">running…</span>}
                    </td>
                    <td className="cell-actions">
                      {can("inventory:write") && (
                        <Button
                          size="sm"
                          icon={<IconRefresh size={14} />}
                          busy={sync.busy}
                          aria-label={`Run ${c.name} now`}
                          onClick={() => void sync.run(c)}
                        >
                          Run now
                        </Button>
                      )}
                      <Button size="sm" variant="ghost" onClick={() => setRunsOf(c)}>
                        Runs
                      </Button>
                      {manage && (
                        <>
                          <Button size="sm" variant="ghost" onClick={() => setEditing(c)}>
                            Edit
                          </Button>
                          <Button size="sm" variant="ghost" busy={remove.busy} onClick={() => void remove.run(c)}>
                            Delete
                          </Button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
      {editing && tid && (
        <ConnectorDialog
          tenant={tid}
          kinds={kinds.data ?? []}
          connector={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={async (c) => {
            setEditing(null);
            toast("good", `${c.name} saved.`);
            await connectors.reload();
          }}
        />
      )}
      {runsOf && tid && <RunsDialog tenant={tid} connector={runsOf} onClose={() => setRunsOf(null)} />}
    </>
  );
}

function ConnectorDialog({
  tenant,
  kinds,
  connector,
  onClose,
  onSaved,
}: {
  tenant: string;
  kinds: ConnectorKind[];
  connector: Connector | null;
  onClose: () => void;
  onSaved: (c: Connector) => void | Promise<void>;
}) {
  const { api } = useSession();
  const [kind, setKind] = useState(connector?.kind ?? kinds[0]?.kind ?? "gateway");
  const [name, setName] = useState(connector?.name ?? "");
  const [environment, setEnvironment] = useState<Environment | "">(connector?.environment ?? "");
  const [intervalMinutes, setIntervalMinutes] = useState(connector?.interval_minutes ?? 60);
  const [enabled, setEnabled] = useState(connector?.enabled ?? true);
  const [configText, setConfigText] = useState(
    JSON.stringify(connector?.config ?? CONNECTOR_EXAMPLES[kind] ?? {}, null, 2),
  );
  const parsed = parseConfig(configText);
  const info = kinds.find((k) => k.kind === kind);

  const save = useAction(async () => {
    if (!parsed.config) return;
    const body = {
      name: name.trim(),
      config: parsed.config,
      environment: environment || null,
      interval_minutes: intervalMinutes,
      enabled,
    };
    const saved = connector
      ? await api.updateConnector(tenant, connector.id, body)
      : await api.createConnector(tenant, { kind, ...body });
    await onSaved(saved);
  });

  return (
    <Dialog
      open
      wide
      title={connector ? `Edit ${connector.name}` : "New discovery connector"}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            busy={save.busy}
            disabled={!name.trim() || !parsed.config}
            onClick={() => void save.run()}
          >
            {connector ? "Save" : "Create connector"}
          </Button>
        </>
      }
    >
      <ErrorBanner error={save.error} />
      <div className="form-row">
        <Field label="Source" htmlFor="c-kind">
          <select
            id="c-kind"
            className="select"
            value={kind}
            disabled={connector !== null}
            onChange={(e) => {
              setKind(e.target.value);
              setConfigText(JSON.stringify(CONNECTOR_EXAMPLES[e.target.value] ?? {}, null, 2));
            }}
          >
            {kinds.map((k) => (
              <option key={k.kind} value={k.kind}>
                {k.title}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Name" htmlFor="c-name">
          <input id="c-name" className="input" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
        </Field>
      </div>
      {info && <p className="muted">{info.description}</p>}
      <div className="form-row">
        <Field label="Environment it covers" htmlFor="c-env" hint="Used for coverage and finding severity.">
          <select
            id="c-env"
            className="select"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value as Environment | "")}
          >
            <option value="">Not one environment</option>
            {ENVIRONMENTS.map((env) => (
              <option key={env} value={env}>
                {env}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Run every (minutes)" htmlFor="c-interval">
          <input
            id="c-interval"
            className="input"
            type="number"
            min={5}
            max={10080}
            value={intervalMinutes}
            onChange={(e) => setIntervalMinutes(Number(e.target.value))}
          />
        </Field>
      </div>
      <label className="check">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Run on schedule
      </label>
      <Field
        label="Configuration (JSON)"
        htmlFor="c-config"
        hint="Credentials are names of DISCOVERY_SECRET_* variables set on the control plane, never the secret itself."
      >
        <textarea id="c-config" className="textarea" value={configText} onChange={(e) => setConfigText(e.target.value)} />
      </Field>
      {parsed.error && <Notice tone="warning">{parsed.error}</Notice>}
      {info && (
        <details>
          <summary className="muted">All settings for {info.title}</summary>
          <pre className="json config-help">{JSON.stringify(info.config_schema.properties ?? {}, null, 2)}</pre>
        </details>
      )}
    </Dialog>
  );
}

function RunsDialog({ tenant, connector, onClose }: { tenant: string; connector: Connector; onClose: () => void }) {
  const { api } = useSession();
  const runs = useResource(() => api.connectorRuns(tenant, connector.id), [api, tenant, connector.id]);
  return (
    <Dialog open wide title={`Runs of ${connector.name}`} onClose={onClose}>
      <ErrorBanner error={runs.error} />
      {runs.data === undefined ? (
        <Loading />
      ) : runs.data.length === 0 ? (
        <EmptyState title="Not run yet" />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Started</th>
                <th scope="col">Status</th>
                <th scope="col" className="num">
                  Observations
                </th>
                <th scope="col" className="num">
                  New / updated
                </th>
                <th scope="col" className="num">
                  Findings
                </th>
              </tr>
            </thead>
            <tbody>{runs.data.map((r) => <RunRow key={r.id} run={r} />)}</tbody>
          </table>
        </div>
      )}
    </Dialog>
  );
}

function RunRow({ run }: { run: SyncRun }) {
  return (
    <tr>
      <td className="nowrap">
        {dateTime(run.started_at)}
        <span className="cell-sub">by {run.triggered_by}</span>
      </td>
      <td>
        <Badge tone={runTone(run.status)}>{run.status}</Badge>
        {run.error && <span className="cell-sub">{run.error}</span>}
        {run.warnings.slice(0, 3).map((w) => (
          <span key={w} className="cell-sub">
            {w}
          </span>
        ))}
      </td>
      <td className="num">{run.observations}</td>
      <td className="num">
        {run.entities_created} / {run.entities_updated}
      </td>
      <td className="num">
        <Mono>
          +{run.findings_opened} −{run.findings_resolved}
        </Mono>
      </td>
    </tr>
  );
}
