// Agent inventory: every agent the discovery connectors found, reconciled against the registry.
// Managed = registered and calling through the gateway; shadow = agent-like and unregistered;
// registered-unmanaged = registered but going around the gateway; stale = not seen for 30 days.

import { useState } from "react";

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
  KeyValue,
  Loading,
  Mono,
  Notice,
  PageHeader,
  Segmented,
} from "../components/ui";
import {
  FINDING_LABEL,
  STATE_HELP,
  STATE_LABEL,
  canBeAgent,
  definitionChange,
  severityTone,
  sourcesOf,
  stateTone,
  suggestAgentId,
} from "../lib/inventory";
import { compact, dateTime, percent, relativeTime } from "../lib/format";
import { useAction, useNow, useResource } from "../lib/hooks";
import { navigate, useQueryParam, useRoute } from "../lib/router";
import { useSession } from "../lib/session";
import {
  AGENT_STATES,
  type EntityState,
  type Finding,
  type FindingStatus,
  type InventoryEntity,
} from "../lib/types";

type View = "agents" | "findings" | "all";

export function InventoryPage() {
  const { api } = useSession();
  const route = useRoute();
  const { tenants, tenant, setTenant, error: tenantsError } = useTenantChoice();
  const [viewParam, setView] = useQueryParam(route, "view");
  const [stateParam, setState] = useQueryParam(route, "state");
  const [entityParam, setEntity] = useQueryParam(route, "entity");
  const [q, setQ] = useState("");
  const view: View = viewParam === "findings" || viewParam === "all" ? viewParam : "agents";
  const state = (AGENT_STATES as string[]).includes(stateParam) ? (stateParam as EntityState) : "";
  const now = useNow(30_000);
  const tid = tenant?.id ?? "";

  const coverage = useResource(() => (tid ? api.coverage(tid) : Promise.resolve(undefined)), [api, tid], 30_000);
  const entities = useResource(
    () =>
      tid && view !== "findings"
        ? api.entities(tid, { agents_only: view === "agents", state, q: q.trim() || undefined })
        : Promise.resolve([] as InventoryEntity[]),
    [api, tid, view, state, q],
    30_000,
  );
  const findings = useResource(
    () => (tid ? api.findings(tid, { status: "open" }) : Promise.resolve([] as Finding[])),
    [api, tid],
    30_000,
  );

  const cov = coverage.data;
  const openFindings = findings.data ?? [];

  return (
    <>
      <PageHeader
        title="Agent inventory"
        description="Every agent the discovery connectors found, compared with the registry. Shadow agents are the difference."
        actions={<TenantPicker tenants={tenants} tenant={tenant} onChange={setTenant} />}
      />
      <ErrorBanner error={tenantsError ?? coverage.error ?? entities.error ?? findings.error} />
      {tenants === undefined ? (
        <Loading />
      ) : !tenant ? (
        <Card>
          <EmptyState title="No tenants yet" />
        </Card>
      ) : (
        <div className="stack">
          <div className="grid-stats">
            <div className="stat">
              <span className="stat-label">Agent coverage</span>
              <span className="stat-value">{cov ? percent(cov.agent_coverage, 0) : "—"}</span>
              <span className="stat-hint">
                {cov ? `${cov.by_state.managed} of ${cov.active_agents} active agents managed` : ""}
              </span>
              {cov && cov.agent_coverage !== null && (
                <div className="meter" aria-hidden="true">
                  <span style={{ width: `${Math.round(cov.agent_coverage * 100)}%` }} />
                </div>
              )}
            </div>
            <StateTile label="Shadow agents" n={cov?.by_state.shadow} onClick={() => go("shadow")} />
            <StateTile label="Registered, unmanaged" n={cov?.by_state.registered_unmanaged} onClick={() => go("registered_unmanaged")} />
            <StateTile label="Stale" n={cov?.by_state.stale} onClick={() => go("stale")} />
            <button type="button" className="stat stat-link" onClick={() => setView("findings")}>
              <span className="stat-label">Open findings</span>
              <span className="stat-value">{findings.data ? openFindings.length : "—"}</span>
              <span className="stat-hint">
                {(["high", "medium", "low"] as const).map((s) => {
                  const n = openFindings.filter((f) => f.severity === s).length;
                  return n ? (
                    <Badge key={s} tone={severityTone(s)}>
                      {n} {s}
                    </Badge>
                  ) : null;
                })}
              </span>
            </button>
          </div>
          {cov && cov.connectors.length === 0 && (
            <Notice tone="info">
              No discovery connectors for this tenant yet. A platform admin adds them under{" "}
              <a href={`#/connectors?tenant=${tid}`}>Discovery connectors</a>; registered agents are listed meanwhile.
            </Notice>
          )}
          {cov && (
            <p className="muted">
              Gateway requests (7 days): <strong>{compact(cov.volume.gateway_requests)}</strong>
              {Object.entries(cov.volume.direct_outside_gateway).map(([unit, n]) => (
                <span key={unit}>
                  {" "}
                  · model traffic outside the gateway: <strong>{compact(n)}</strong> {unit.replace("_", " ")}
                </span>
              ))}
            </p>
          )}

          <Segmented<View>
            label="Inventory view"
            value={view}
            onChange={(v) => setView(v)}
            options={[
              { value: "agents", label: "Agents" },
              { value: "findings", label: "Findings", count: findings.data ? openFindings.length : undefined },
              { value: "all", label: "Everything" },
            ]}
          />

          {view === "findings" ? (
            <FindingsCard tenant={tid} findings={findings.data} onOpen={(id) => setEntity(id)} onChanged={() => void Promise.all([findings.reload(), coverage.reload()])} now={now} />
          ) : (
            <Card
              flush
              title={view === "agents" ? "Agents" : "Everything discovered"}
              actions={
                <div className="row">
                  {view === "agents" && (
                    <select
                      aria-label="Filter by state"
                      className="select select-auto"
                      value={state}
                      onChange={(e) => setState(e.target.value || null)}
                    >
                      <option value="">All states</option>
                      {AGENT_STATES.map((s) => (
                        <option key={s} value={s}>
                          {STATE_LABEL[s]}
                        </option>
                      ))}
                    </select>
                  )}
                  <input
                    aria-label="Search"
                    className="input select-auto"
                    placeholder="Search name or key"
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                  />
                </div>
              }
            >
              {entities.data === undefined ? (
                <Loading />
              ) : entities.data.length === 0 ? (
                <EmptyState title={view === "agents" ? "No agents found" : "Nothing discovered yet"}>
                  Run a connector (Discovery connectors) or widen the filter.
                </EmptyState>
              ) : (
                <EntityTable items={entities.data} now={now} onOpen={(id) => setEntity(id)} />
              )}
            </Card>
          )}
        </div>
      )}
      {tid && entityParam && (
        <EntityDialog
          tenant={tid}
          entityId={entityParam}
          onClose={() => setEntity(null)}
          onChanged={() => void Promise.all([entities.reload(), coverage.reload(), findings.reload()])}
          onMerged={(id) => setEntity(id)}
        />
      )}
    </>
  );

  function go(s: EntityState) {
    navigate(route.path, { ...route.query, view: "agents", state: s });
  }
}

function StateTile({ label, n, onClick }: { label: string; n: number | undefined; onClick: () => void }) {
  return (
    <button type="button" className="stat stat-link" onClick={onClick}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{n ?? "—"}</span>
    </button>
  );
}

export function StateBadge({ state }: { state: EntityState }) {
  return (
    <span title={STATE_HELP[state]}>
      <Badge tone={stateTone(state)}>{STATE_LABEL[state]}</Badge>
    </span>
  );
}

function EntityTable({ items, now, onOpen }: { items: InventoryEntity[]; now: number; onOpen: (id: string) => void }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">State</th>
            <th scope="col">Registry</th>
            <th scope="col">Owner</th>
            <th scope="col">Seen by</th>
            <th scope="col">Last seen</th>
            <th scope="col" className="num">
              Gateway / direct
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.id} className="clickable" onClick={() => onOpen(e.id)}>
              <td>
                <button type="button" className="link-btn" onClick={() => onOpen(e.id)}>
                  {e.name}
                </button>
                <span className="cell-sub">
                  {e.kind}
                  {e.environment ? ` · ${e.environment}` : ""}
                  {e.agent_likelihood === "probable" ? " · probable agent" : ""}
                </span>
              </td>
              <td>
                <StateBadge state={e.state} />
                {e.ignored_until && Date.parse(e.ignored_until) > now && <span className="cell-sub">ignored</span>}
              </td>
              <td>{e.registry_agent_id ? <Mono>{e.registry_agent_id}</Mono> : <span className="muted">—</span>}</td>
              <td>{e.owner_guess ?? <span className="muted">unknown</span>}</td>
              <td>
                {sourcesOf(e).map((s) => (
                  <span key={s.id} className="tag" title={s.connector}>
                    {s.kind}
                  </span>
                ))}
              </td>
              <td className="nowrap">{relativeTime(e.last_seen, now)}</td>
              <td className="num nowrap">
                {compact(e.managed_volume)} / {compact(e.direct_volume)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingsCard({
  tenant,
  findings,
  onOpen,
  onChanged,
  now,
}: {
  tenant: string;
  findings: Finding[] | undefined;
  onOpen: (entityId: string) => void;
  onChanged: () => void;
  now: number;
}) {
  const { api, can } = useSession();
  const toast = useToast();
  const update = useAction(async (f: Finding, status: FindingStatus) => {
    await api.updateFinding(tenant, f.id, status, status === "accepted" ? "accepted in the console" : "resolved in the console");
    toast("good", status === "accepted" ? "Accepted: it won't be raised again for this item." : "Marked as resolved.");
    onChanged();
  });
  return (
    <Card flush title="Open findings">
      <ErrorBanner error={update.error} />
      {findings === undefined ? (
        <Loading />
      ) : findings.length === 0 ? (
        <EmptyState title="No open findings" />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Finding</th>
                <th scope="col">Raised</th>
                <th scope="col" />
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td>
                    <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                  </td>
                  <td>
                    <button type="button" className="link-btn" onClick={() => onOpen(f.entity_id)}>
                      {f.summary}
                    </button>
                    <span className="cell-sub">{FINDING_LABEL[f.kind] ?? f.kind}</span>
                    <DefinitionChange finding={f} />
                  </td>
                  <td className="nowrap">{relativeTime(f.created_at, now)}</td>
                  <td className="cell-actions">
                    {can("inventory:write") && (
                      <>
                        <Button size="sm" busy={update.busy} onClick={() => void update.run(f, "accepted")}>
                          Accept
                        </Button>
                        <Button size="sm" variant="ghost" busy={update.busy} onClick={() => void update.run(f, "resolved")}>
                          Resolve
                        </Button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/** What changed in an MCP tool's definition: check it before accepting (accepting pins the new one). */
function DefinitionChange({ finding }: { finding: Finding }) {
  const change = definitionChange(finding);
  if (!change) return null;
  return (
    <span className="cell-sub">
      <span className="diff-old">Approved: {change.before || "(no description)"}</span>
      <br />
      <span className="diff-new">Now: {change.after || "(no description)"}</span>
      <br />
      Accept pins the new definition; until then, calls to this tool carry the TOOL_DEFINITION_CHANGED risk signal.
    </span>
  );
}

type Action = null | "register" | "link" | "ignore";

function EntityDialog({
  tenant,
  entityId,
  onClose,
  onChanged,
  onMerged,
}: {
  tenant: string;
  entityId: string;
  onClose: () => void;
  onChanged: () => void;
  /** Linking or registering can merge this entity into another one (the agent's registry entry). */
  onMerged: (entityId: string) => void;
}) {
  const { api, can } = useSession();
  const toast = useToast();
  const now = useNow(30_000);
  const detail = useResource(() => api.entity(tenant, entityId), [api, tenant, entityId]);
  const agents = useResource(() => api.agents(tenant), [api, tenant]);
  const [action, setAction] = useState<Action>(null);
  const [agentId, setAgentId] = useState("");
  const [trust, setTrust] = useState(50);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(30);

  const e = detail.data?.entity;
  const done = async (message: string, result?: { id: string }) => {
    toast("good", message);
    setAction(null);
    onChanged();
    if (result && result.id !== entityId) onMerged(result.id);
    else await detail.reload();
  };
  const register = useAction(async () => {
    const out = await api.registerEntity(tenant, entityId, { agent_id: agentId.trim(), base_trust_score: trust, allowed_tools: [] });
    await done(`Registered as ${agentId.trim()}. Bind a gateway key to it under Tenants & keys.`, out);
  });
  const link = useAction(async () => {
    const out = await api.linkEntity(tenant, entityId, agentId);
    await done(`Linked to ${agentId}.`, out);
  });
  const ignore = useAction(async (d: number) => {
    await api.ignoreEntity(tenant, entityId, reason.trim() || "stop ignoring", d);
    await done(d ? `Ignored for ${d} days.` : "No longer ignored.");
  });
  const err = detail.error ?? register.error ?? link.error ?? ignore.error;
  const writable = can("inventory:write") && e !== undefined && canBeAgent(e.kind);
  const ignored = e?.ignored_until && Date.parse(e.ignored_until) > now;

  return (
    <Dialog open wide title={e ? e.name : "Inventory item"} onClose={onClose}>
      <ErrorBanner error={err} />
      {!detail.data || !e ? (
        <Loading />
      ) : (
        <div className="stack">
          <KeyValue
            items={[
              ["State", <StateBadge key="s" state={e.state} />],
              ["Kind", `${e.kind}${e.agent_likelihood !== "none" ? ` (${e.agent_likelihood} agent)` : ""}`],
              ["Registry agent", e.registry_agent_id ? <Mono key="r">{e.registry_agent_id}</Mono> : "not registered"],
              ["Owner (guess)", e.owner_guess ?? "unknown"],
              ["Environment", e.environment ?? "unknown"],
              ["Seen", `${dateTime(e.first_seen)} – ${relativeTime(e.last_seen, now)}`],
              ["Model traffic (7 days)", `${compact(e.managed_volume)} through the gateway · ${compact(e.direct_volume)} outside it`],
              ["Keys", <span key="k">{e.strong_keys.map((k) => <span key={k} className="tag">{k}</span>)}</span>],
              ...(ignored ? [["Ignored", `until ${dateTime(e.ignored_until)}: ${e.ignore_reason ?? ""}`] as [string, string]] : []),
            ]}
          />
          {e.reasons.length > 0 && (
            <Card title="Why">
              <ul className="plain-list">
                {e.reasons.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </Card>
          )}
          {writable && (
            <div className="row">
              {!e.registry_agent_id && (
                <Button
                  variant="primary"
                  onClick={() => {
                    setAgentId(suggestAgentId(e.name));
                    setAction("register");
                  }}
                >
                  Register agent
                </Button>
              )}
              {!e.registry_agent_id && (
                <Button
                  onClick={() => {
                    setAgentId(agents.data?.[0]?.agent_id ?? "");
                    setAction("link");
                  }}
                >
                  Link to a registered agent
                </Button>
              )}
              {ignored ? (
                <Button variant="ghost" busy={ignore.busy} onClick={() => void ignore.run(0)}>
                  Stop ignoring
                </Button>
              ) : (
                <Button variant="ghost" onClick={() => setAction("ignore")}>
                  Ignore
                </Button>
              )}
            </div>
          )}
          {action === "register" && (
            <Card title="Register this agent">
              <div className="form-row">
                <Field label="Agent id" htmlFor="reg-id" hint="The agent_id its gateway key will be bound to.">
                  <input id="reg-id" className="input" value={agentId} onChange={(ev) => setAgentId(ev.target.value)} />
                </Field>
                <Field label="Base trust (0–100)" htmlFor="reg-trust">
                  <input
                    id="reg-trust"
                    className="input"
                    type="number"
                    min={0}
                    max={100}
                    value={trust}
                    onChange={(ev) => setTrust(Number(ev.target.value))}
                  />
                </Field>
              </div>
              <div className="row">
                <Button variant="primary" busy={register.busy} disabled={!agentId.trim()} onClick={() => void register.run()}>
                  Register
                </Button>
                <Button variant="ghost" onClick={() => setAction(null)}>
                  Cancel
                </Button>
              </div>
            </Card>
          )}
          {action === "link" && (
            <Card title="Link to a registered agent">
              <Field label="Agent" htmlFor="link-agent">
                <select id="link-agent" className="select" value={agentId} onChange={(ev) => setAgentId(ev.target.value)}>
                  {(agents.data ?? []).map((a) => (
                    <option key={a.agent_id} value={a.agent_id}>
                      {a.agent_id}
                    </option>
                  ))}
                </select>
              </Field>
              <div className="row">
                <Button variant="primary" busy={link.busy} disabled={!agentId} onClick={() => void link.run()}>
                  Link
                </Button>
                <Button variant="ghost" onClick={() => setAction(null)}>
                  Cancel
                </Button>
              </div>
            </Card>
          )}
          {action === "ignore" && (
            <Card title="Ignore for a while">
              <div className="form-row">
                <Field label="Reason" htmlFor="ign-reason" hint="Shown on the item and in the activity log.">
                  <input id="ign-reason" className="input" value={reason} onChange={(ev) => setReason(ev.target.value)} />
                </Field>
                <Field label="Days" htmlFor="ign-days">
                  <input
                    id="ign-days"
                    className="input"
                    type="number"
                    min={1}
                    max={365}
                    value={days}
                    onChange={(ev) => setDays(Number(ev.target.value))}
                  />
                </Field>
              </div>
              <div className="row">
                <Button variant="primary" busy={ignore.busy} disabled={!reason.trim()} onClick={() => void ignore.run(days)}>
                  Ignore
                </Button>
                <Button variant="ghost" onClick={() => setAction(null)}>
                  Cancel
                </Button>
              </div>
            </Card>
          )}

          {detail.data.findings.length > 0 && (
            <Card flush title="Findings">
              <table className="table">
                <tbody>
                  {detail.data.findings.map((f) => (
                    <tr key={f.id}>
                      <td>
                        <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                      </td>
                      <td>
                        {f.summary}
                        <span className="cell-sub">
                          {f.status}
                          {f.note ? ` · ${f.note}` : ""}
                        </span>
                      </td>
                      <td className="nowrap">{relativeTime(f.created_at, now)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}

          <Card flush title="Seen by">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Source</th>
                  <th scope="col">Signals</th>
                  <th scope="col">When</th>
                </tr>
              </thead>
              <tbody>
                {sourcesOf(e).map((s) => (
                  <tr key={s.id}>
                    <td>
                      {s.connector}
                      <span className="cell-sub">{s.kind}</span>
                    </td>
                    <td>
                      {s.signals.map((sig) => (
                        <span key={sig} className="tag">
                          {sig}
                        </span>
                      ))}
                    </td>
                    <td className="nowrap">{s.at ? relativeTime(s.at, now) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <Card flush title="Relations">
            {detail.data.relations.length === 0 ? (
              <EmptyState title="No current relations" />
            ) : (
              <table className="table">
                <tbody>
                  {detail.data.relations.map((r) => (
                    <tr key={r.edge.id}>
                      <td className="nowrap">{r.direction === "out" ? r.edge.kind : `← ${r.edge.kind}`}</td>
                      <td>
                        {r.other ? r.other.name : <Mono>{r.direction === "out" ? r.edge.dst : r.edge.src}</Mono>}
                        <span className="cell-sub">{r.other?.kind}</span>
                      </td>
                      <td className="nowrap">since {dateTime(r.edge.valid_from)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          <Card flush title="Evidence">
            <table className="table">
              <tbody>
                {detail.data.evidence.slice(0, 10).map((o) => (
                  <tr key={o.id}>
                    <td>
                      {o.kind}
                      <span className="cell-sub">
                        <Mono>{o.source_ref}</Mono>
                      </span>
                    </td>
                    <td className="nowrap">{relativeTime(o.observed_at, now)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>
      )}
    </Dialog>
  );
}
