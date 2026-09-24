// Tenant catalog: gateway API keys, agent profiles (base trust), the action catalog (base risk) and
// score modifiers. Every change is published to gateways automatically within seconds.

import { useState, type ReactNode } from "react";

import { IconEdit, IconPlus, IconTrash } from "../components/icons";
import { useToast } from "../components/toast";
import {
  Badge,
  Button,
  Card,
  CopyButton,
  Dialog,
  EmptyState,
  ErrorBanner,
  Field,
  Loading,
  Mono,
  Notice,
  PageHeader,
  Segmented,
} from "../components/ui";
import { dateTime, relativeTime } from "../lib/format";
import { useAction, useResource } from "../lib/hooks";
import { useQueryParam, useRoute } from "../lib/router";
import { useSession } from "../lib/session";
import {
  ENVIRONMENTS,
  type ActionRule,
  type Agent,
  type ApiKey,
  type CreatedApiKey,
  type Environment,
  type Modifier,
  type Tenant,
} from "../lib/types";

type Tab = "keys" | "agents" | "actions" | "modifiers";

export function keyState(k: ApiKey, now = Date.now()): { label: string; tone: "good" | "neutral" | "critical" } {
  if (!k.is_active || k.revoked_at) return { label: "revoked", tone: "critical" };
  if (k.expires_at && Date.parse(k.expires_at) <= now) return { label: "expired", tone: "neutral" };
  return { label: "active", tone: "good" };
}

export function CatalogPage() {
  const { api, me, can } = useSession();
  const toast = useToast();
  const route = useRoute();
  const [tenantParam, setTenant] = useQueryParam(route, "tenant");
  const [tabParam, setTab] = useQueryParam(route, "tab");
  const tab = (["keys", "agents", "actions", "modifiers"].includes(tabParam) ? tabParam : "keys") as Tab;
  const tenants = useResource(() => api.tenants(), [api]);
  const [creating, setCreating] = useState(false);

  const list = tenants.data ?? [];
  const selected = list.find((t) => t.id === tenantParam) ?? list[0];

  const setStatus = useAction(async (t: Tenant) => {
    const next = t.status === "active" ? "suspended" : "active";
    await api.setTenantStatus(t.id, next);
    toast("good", next === "suspended" ? `${t.name} is suspended: its keys stop working.` : `${t.name} is active again.`);
    await tenants.reload();
  });

  return (
    <>
      <PageHeader
        title="Tenants & keys"
        description="Gateway API keys and the scores the gateway uses: agent trust, action risk and modifiers. Changes reach gateways within seconds."
        actions={
          me.platform &&
          can("catalog:write") && (
            <Button icon={<IconPlus size={14} />} onClick={() => setCreating(true)}>
              New tenant
            </Button>
          )
        }
      />
      <ErrorBanner error={tenants.error ?? setStatus.error} />
      {tenants.data === undefined ? (
        <Loading />
      ) : list.length === 0 ? (
        <Card>
          <EmptyState title="No tenants yet">Create a tenant, then give its agents a gateway API key.</EmptyState>
        </Card>
      ) : (
        <div className="split split-narrow">
          <Card flush title="Tenants">
            <table className="table">
              <tbody>
                {list.map((t) => (
                  <tr
                    key={t.id}
                    className={t.id === selected?.id ? "clickable selected" : "clickable"}
                    onClick={() => setTenant(t.id)}
                  >
                    <td>
                      <button type="button" className="link-btn" onClick={() => setTenant(t.id)}>
                        {t.name}
                      </button>
                      <span className="cell-sub">{t.id}</span>
                    </td>
                    <td className="num">
                      {t.status === "active" ? <Badge tone="good">active</Badge> : <Badge tone="critical">suspended</Badge>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          {selected && (
            <Card
              title={
                <span className="row">
                  {selected.name} <Mono>{selected.id}</Mono>
                </span>
              }
              actions={
                me.platform &&
                can("catalog:write") && (
                  <Button
                    size="sm"
                    variant="secondary"
                    busy={setStatus.busy}
                    onClick={() => void setStatus.run(selected)}
                  >
                    {selected.status === "active" ? "Suspend tenant" : "Reactivate tenant"}
                  </Button>
                )
              }
            >
              {selected.status === "suspended" && (
                <Notice tone="warning">This tenant is suspended: none of its keys work and nothing is scored for it.</Notice>
              )}
              <div className="toolbar">
                <Segmented<Tab>
                  label="Section"
                  value={tab}
                  onChange={(v) => setTab(v === "keys" ? null : v)}
                  options={[
                    { value: "keys", label: "API keys" },
                    { value: "agents", label: "Agents" },
                    { value: "actions", label: "Actions" },
                    { value: "modifiers", label: "Modifiers" },
                  ]}
                />
              </div>
              {tab === "keys" && <KeysTab tenant={selected.id} />}
              {tab === "agents" && <AgentsTab tenant={selected.id} />}
              {tab === "actions" && <ActionsTab tenant={selected.id} />}
              {tab === "modifiers" && <ModifiersTab tenant={selected.id} />}
            </Card>
          )}
        </div>
      )}
      {creating && (
        <CreateTenantDialog
          onClose={() => setCreating(false)}
          onDone={async (t) => {
            setCreating(false);
            toast("good", `Created tenant ${t.id}.`);
            await tenants.reload();
            setTenant(t.id);
          }}
        />
      )}
    </>
  );
}

function CreateTenantDialog({ onClose, onDone }: { onClose: () => void; onDone: (t: Tenant) => Promise<void> }) {
  const { api } = useSession();
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const create = useAction(async () => onDone(await api.createTenant(id.trim(), name.trim())));
  const validId = /^[a-z0-9][a-z0-9-]{1,62}$/.test(id.trim());
  return (
    <Dialog
      open
      title="New tenant"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={create.busy} disabled={!validId || !name.trim()} onClick={() => void create.run()}>
            Create
          </Button>
        </>
      }
    >
      <Field label="Tenant ID" htmlFor="t-id" hint="Lowercase letters, digits and hyphens. It can't be changed later.">
        <input id="t-id" className="input" value={id} onChange={(e) => setId(e.target.value)} placeholder="acme" />
      </Field>
      <Field label="Name" htmlFor="t-name">
        <input id="t-name" className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" />
      </Field>
      <ErrorBanner error={create.error} />
    </Dialog>
  );
}

// ---- tabs ---------------------------------------------------------------------------------------

function TabTable({ head, children, empty }: { head: string[]; children: ReactNode[]; empty: string }) {
  if (children.length === 0) return <EmptyState title={empty} />;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            {head.map((h, i) => (
              <th key={i} scope="col" className={h.startsWith("#") ? "num" : undefined}>
                {h.replace(/^#/, "") || <span className="sr-only">Actions</span>}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

function KeysTab({ tenant }: { tenant: string }) {
  const { api, can } = useSession();
  const toast = useToast();
  const keys = useResource(() => api.apiKeys(tenant), [api, tenant]);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreatedApiKey | null>(null);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  const [limiting, setLimiting] = useState<ApiKey | null>(null);
  const revoke = useAction(async (k: ApiKey) => {
    await api.revokeApiKey(tenant, k.id);
    toast("good", `Revoked ${k.name}. Gateways reject it within seconds.`);
    setRevoking(null);
    await keys.reload();
  });
  const editable = can("catalog:write");
  return (
    <>
      <div className="row toolbar">
        {editable && (
          <Button size="sm" icon={<IconPlus size={14} />} onClick={() => setCreating(true)}>
            New API key
          </Button>
        )}
      </div>
      <ErrorBanner error={keys.error} />
      {keys.data === undefined ? (
        <Loading />
      ) : (
        <TabTable head={["Name", "Environments", "Rate limit", "Status", "Created", ""]} empty="No API keys">
          {keys.data.map((k) => {
            const st = keyState(k);
            return (
              <tr key={k.id}>
                <td>
                  {k.name}
                  <span className="cell-sub">
                    <Mono>{k.prefix}…</Mono> · {k.scopes.join(", ")}
                  </span>
                </td>
                <td>{k.environments ? k.environments.join(", ") : "all"}</td>
                <td>{rateLabel(k.rate_limit_per_minute)}</td>
                <td>
                  <Badge tone={st.tone}>{st.label}</Badge>
                  {k.expires_at && st.label === "active" && <span className="cell-sub">expires {relativeTime(k.expires_at)}</span>}
                </td>
                <td>{dateTime(k.created_at)}</td>
                <td>
                  {editable && st.label === "active" && (
                    <div className="cell-actions">
                      <Button size="sm" variant="ghost" onClick={() => setLimiting(k)}>
                        Limit
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setRevoking(k)}>
                        Revoke
                      </Button>
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </TabTable>
      )}
      {creating && (
        <CreateKeyDialog
          tenant={tenant}
          onClose={() => setCreating(false)}
          onDone={async (k) => {
            setCreating(false);
            setCreated(k);
            await keys.reload();
          }}
        />
      )}
      <Dialog open={created !== null} title="Copy the new API key" onClose={() => setCreated(null)}
        footer={<Button variant="primary" onClick={() => setCreated(null)}>I've stored it</Button>}>
        {created && (
          <div className="stack">
            <Notice tone="warning">This is the only time the key is shown. Only its hash is kept.</Notice>
            <div className="secret">
              <span>{created.key}</span>
              <CopyButton text={created.key} />
            </div>
            <p className="muted">Agents send it in the X-API-Key header to the gateway.</p>
          </div>
        )}
      </Dialog>
      {limiting && (
        <RateLimitDialog
          tenant={tenant}
          apiKey={limiting}
          onClose={() => setLimiting(null)}
          onDone={async () => {
            setLimiting(null);
            toast("good", "Rate limit saved. Gateways apply it within seconds.");
            await keys.reload();
          }}
        />
      )}
      <Dialog
        open={revoking !== null}
        title={`Revoke ${revoking?.name ?? ""}?`}
        onClose={() => setRevoking(null)}
        footer={
          <>
            <Button onClick={() => setRevoking(null)}>Cancel</Button>
            <Button variant="danger" busy={revoke.busy} onClick={() => revoking && void revoke.run(revoking)}>
              Revoke
            </Button>
          </>
        }
      >
        <p>Agents using this key are rejected within a few seconds. This can't be undone.</p>
        <ErrorBanner error={revoke.error} />
      </Dialog>
    </>
  );
}

function CreateKeyDialog({
  tenant,
  onClose,
  onDone,
}: {
  tenant: string;
  onClose: () => void;
  onDone: (k: CreatedApiKey) => Promise<void>;
}) {
  const { api } = useSession();
  const [name, setName] = useState("");
  const [envs, setEnvs] = useState<Environment[]>([]);
  const [expires, setExpires] = useState("");
  const [limit, setLimit] = useState("");
  const create = useAction(async () =>
    onDone(
      await api.createApiKey(tenant, {
        name: name.trim(),
        environments: envs.length > 0 ? envs : null,
        expires_at: expires ? new Date(`${expires}T23:59:59`).toISOString() : null,
        rate_limit_per_minute: limit === "" ? null : Number(limit),
      }),
    ),
  );
  return (
    <Dialog
      open
      title={`New API key for ${tenant}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={create.busy} disabled={!name.trim()} onClick={() => void create.run()}>
            Create key
          </Button>
        </>
      }
    >
      <Field label="Name" htmlFor="k-name" hint="Usually the agent that will use it">
        <input id="k-name" className="input" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Environments" hint="Leave all unticked to allow every environment">
        <div>
          {ENVIRONMENTS.map((e) => (
            <label key={e} className="check">
              <input
                type="checkbox"
                checked={envs.includes(e)}
                onChange={() => setEnvs((cur) => (cur.includes(e) ? cur.filter((x) => x !== e) : [...cur, e]))}
              />
              {e}
            </label>
          ))}
        </div>
      </Field>
      <Field label="Expires" htmlFor="k-exp" hint="Optional">
        <input id="k-exp" className="input" type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
      </Field>
      <Field label="Rate limit (requests per minute)" htmlFor="k-limit" hint="Empty = the gateway default; 0 = unlimited.">
        <input id="k-limit" className="input" type="number" min={0} value={limit} onChange={(e) => setLimit(e.target.value)} />
      </Field>
      <ErrorBanner error={create.error} />
    </Dialog>
  );
}

export function rateLabel(perMinute: number | null | undefined): string {
  if (perMinute === null || perMinute === undefined) return "default";
  return perMinute === 0 ? "unlimited" : `${perMinute}/min`;
}

function RateLimitDialog({
  tenant,
  apiKey,
  onClose,
  onDone,
}: {
  tenant: string;
  apiKey: ApiKey;
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const { api } = useSession();
  const current = apiKey.rate_limit_per_minute;
  const [value, setValue] = useState(current === null || current === undefined ? "" : String(current));
  const save = useAction(async () => {
    await api.setApiKeyRateLimit(tenant, apiKey.id, value === "" ? null : Number(value));
    await onDone();
  });
  return (
    <Dialog
      open
      title={`Rate limit for ${apiKey.name}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={save.busy} disabled={value !== "" && Number(value) < 0} onClick={() => void save.run()}>
            Save
          </Button>
        </>
      }
    >
      <Field
        label="Requests per minute, per gateway replica"
        htmlFor="rl-value"
        hint="Empty = the gateway default (GUARD_RATE_LIMIT_PER_MINUTE); 0 = unlimited. Over the limit, the gateway answers 429."
      >
        <input id="rl-value" className="input" type="number" min={0} value={value} onChange={(e) => setValue(e.target.value)} />
      </Field>
      <ErrorBanner error={save.error} />
    </Dialog>
  );
}

function AgentsTab({ tenant }: { tenant: string }) {
  const { api, can } = useSession();
  const toast = useToast();
  const agents = useResource(() => api.agents(tenant), [api, tenant]);
  const [editing, setEditing] = useState<Agent | "new" | null>(null);
  const del = useAction(async (a: Agent) => {
    await api.deleteAgent(tenant, a.agent_id);
    toast("good", `Removed ${a.agent_id}. Requests from it now get trust 0.`);
    await agents.reload();
  });
  const editable = can("catalog:write");
  return (
    <>
      <div className="row toolbar">
        {editable && (
          <Button size="sm" icon={<IconPlus size={14} />} onClick={() => setEditing("new")}>
            Add agent
          </Button>
        )}
      </div>
      <p className="field-hint">An agent that isn't listed gets trust 0, so production policy denies it.</p>
      <ErrorBanner error={agents.error ?? del.error} />
      {agents.data === undefined ? (
        <Loading />
      ) : (
        <TabTable head={["Agent", "#Trust", "Allowed tools", ""]} empty="No agents">
          {agents.data.map((a) => (
            <tr key={a.agent_id}>
              <td>
                {a.agent_id}
                {a.owner && <span className="cell-sub">{a.owner}</span>}
              </td>
              <td className="num">{a.base_trust_score}</td>
              <td>
                {a.allowed_tools.map((t) => (
                  <span key={t} className="tag">
                    {t}
                  </span>
                ))}
              </td>
              <td>
                {editable && (
                  <div className="cell-actions">
                    <button type="button" className="icon-btn" aria-label={`Edit ${a.agent_id}`} onClick={() => setEditing(a)}>
                      <IconEdit size={15} />
                    </button>
                    <button type="button" className="icon-btn" aria-label={`Remove ${a.agent_id}`} onClick={() => void del.run(a)}>
                      <IconTrash size={15} />
                    </button>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </TabTable>
      )}
      {editing && (
        <AgentDialog
          tenant={tenant}
          initial={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onDone={async () => {
            setEditing(null);
            toast("good", "Agent saved.");
            await agents.reload();
          }}
        />
      )}
    </>
  );
}

function AgentDialog({
  tenant,
  initial,
  onClose,
  onDone,
}: {
  tenant: string;
  initial: Agent | null;
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const { api } = useSession();
  const [id, setId] = useState(initial?.agent_id ?? "");
  const [trust, setTrust] = useState(String(initial?.base_trust_score ?? 50));
  const [tools, setTools] = useState((initial?.allowed_tools ?? ["*"]).join(", "));
  const [owner, setOwner] = useState(initial?.owner ?? "");
  const save = useAction(async () => {
    await api.putAgent(tenant, id.trim(), {
      base_trust_score: Number(trust),
      allowed_tools: tools
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
      owner: owner.trim() || null,
    });
    await onDone();
  });
  const n = Number(trust);
  return (
    <Dialog
      open
      title={initial ? `Edit ${initial.agent_id}` : "Add agent"}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            busy={save.busy}
            disabled={!id.trim() || !(n >= 0 && n <= 100)}
            onClick={() => void save.run()}
          >
            Save
          </Button>
        </>
      }
    >
      <Field label="Agent ID" htmlFor="ag-id">
        <input id="ag-id" className="input" value={id} disabled={!!initial} onChange={(e) => setId(e.target.value)} />
      </Field>
      <Field label="Base trust (0–100)" htmlFor="ag-trust" hint="Production policy denies trust below 50.">
        <input id="ag-trust" className="input" type="number" min={0} max={100} value={trust} onChange={(e) => setTrust(e.target.value)} />
      </Field>
      <Field label="Allowed tools" htmlFor="ag-tools" hint="Comma-separated; * allows every tool, crm.* a prefix.">
        <input id="ag-tools" className="input" value={tools} onChange={(e) => setTools(e.target.value)} />
      </Field>
      <Field label="Owner" htmlFor="ag-owner" hint="Optional">
        <input id="ag-owner" className="input" value={owner} onChange={(e) => setOwner(e.target.value)} />
      </Field>
      <ErrorBanner error={save.error} />
    </Dialog>
  );
}

function ActionsTab({ tenant }: { tenant: string }) {
  const { api, can } = useSession();
  const toast = useToast();
  const actions = useResource(() => api.actions(tenant), [api, tenant]);
  const [adding, setAdding] = useState<ActionRule | "new" | null>(null);
  const del = useAction(async (a: ActionRule) => {
    await api.deleteAction(tenant, a.id);
    toast("good", `Removed ${a.action}. It now scores risk 100.`);
    await actions.reload();
  });
  const editable = can("catalog:write");
  return (
    <>
      <div className="row toolbar">
        {editable && (
          <Button size="sm" icon={<IconPlus size={14} />} onClick={() => setAdding("new")}>
            Add action
          </Button>
        )}
      </div>
      <p className="field-hint">risk = min(100, action base + classification modifier + environment modifier). Unknown actions score 100.</p>
      <ErrorBanner error={actions.error ?? del.error} />
      {actions.data === undefined ? (
        <Loading />
      ) : (
        <TabTable head={["Action", "Resource", "#Base risk", ""]} empty="No actions">
          {actions.data.map((a) => (
            <tr key={a.id}>
              <td>
                <Mono>{a.action}</Mono>
              </td>
              <td>
                <Mono>{a.resource_pattern}</Mono>
              </td>
              <td className="num">{a.base_risk_score}</td>
              <td>
                {editable && (
                  <div className="cell-actions">
                    <button type="button" className="icon-btn" aria-label={`Edit ${a.action}`} onClick={() => setAdding(a)}>
                      <IconEdit size={15} />
                    </button>
                    <button type="button" className="icon-btn" aria-label={`Remove ${a.action}`} onClick={() => void del.run(a)}>
                      <IconTrash size={15} />
                    </button>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </TabTable>
      )}
      {adding && (
        <ScoreDialog
          title={adding === "new" ? "Add action" : `Edit ${adding.action}`}
          fields={[
            { key: "action", label: "Action", initial: adding === "new" ? "" : adding.action, locked: adding !== "new", placeholder: "database.read" },
            { key: "resource_pattern", label: "Resource pattern", initial: adding === "new" ? "*" : adding.resource_pattern, locked: adding !== "new" },
          ]}
          number={{ label: "Base risk (0–100)", initial: adding === "new" ? 30 : adding.base_risk_score, min: 0, max: 100 }}
          onClose={() => setAdding(null)}
          onSave={async (v, n) => {
            await api.putAction(tenant, { action: v.action ?? "", resource_pattern: v.resource_pattern || "*", base_risk_score: n });
            setAdding(null);
            toast("good", "Action saved.");
            await actions.reload();
          }}
        />
      )}
    </>
  );
}

function ModifiersTab({ tenant }: { tenant: string }) {
  const { api, can } = useSession();
  const toast = useToast();
  const mods = useResource(() => api.modifiers(tenant), [api, tenant]);
  const [adding, setAdding] = useState<Modifier | "new" | null>(null);
  const del = useAction(async (m: Modifier) => {
    await api.deleteModifier(tenant, m.id);
    toast("good", "Modifier removed.");
    await mods.reload();
  });
  const editable = can("catalog:write");
  return (
    <>
      <div className="row toolbar">
        {editable && (
          <Button size="sm" icon={<IconPlus size={14} />} onClick={() => setAdding("new")}>
            Add modifier
          </Button>
        )}
      </div>
      <ErrorBanner error={mods.error ?? del.error} />
      {mods.data === undefined ? (
        <Loading />
      ) : (
        <TabTable head={["Kind", "Value", "#Delta", ""]} empty="No modifiers">
          {mods.data.map((m) => (
            <tr key={m.id}>
              <td>{m.kind}</td>
              <td>
                <Mono>{m.value}</Mono>
              </td>
              <td className="num">{m.delta > 0 ? `+${m.delta}` : m.delta}</td>
              <td>
                {editable && (
                  <div className="cell-actions">
                    <button type="button" className="icon-btn" aria-label={`Edit ${m.kind} ${m.value}`} onClick={() => setAdding(m)}>
                      <IconEdit size={15} />
                    </button>
                    <button type="button" className="icon-btn" aria-label={`Remove ${m.kind} ${m.value}`} onClick={() => void del.run(m)}>
                      <IconTrash size={15} />
                    </button>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </TabTable>
      )}
      {adding && (
        <ScoreDialog
          title={adding === "new" ? "Add modifier" : "Edit modifier"}
          fields={[
            {
              key: "kind",
              label: "Kind",
              initial: adding === "new" ? "classification" : adding.kind,
              locked: adding !== "new",
              options: ["classification", "environment"],
            },
            {
              key: "value",
              label: "Value",
              initial: adding === "new" ? "" : adding.value,
              locked: adding !== "new",
              placeholder: "PII, CONFIDENTIAL, production…",
            },
          ]}
          number={{ label: "Delta (−100 to 100)", initial: adding === "new" ? 10 : adding.delta, min: -100, max: 100 }}
          onClose={() => setAdding(null)}
          onSave={async (v, n) => {
            await api.putModifier(tenant, { kind: (v.kind ?? "classification") as Modifier["kind"], value: v.value ?? "", delta: n });
            setAdding(null);
            toast("good", "Modifier saved.");
            await mods.reload();
          }}
        />
      )}
    </>
  );
}

/** Small form for catalog rows: a few text/select fields plus one bounded number. */
function ScoreDialog({
  title,
  fields,
  number,
  onClose,
  onSave,
}: {
  title: string;
  fields: { key: string; label: string; initial: string; locked?: boolean; placeholder?: string; options?: string[] }[];
  number: { label: string; initial: number; min: number; max: number };
  onClose: () => void;
  onSave: (values: Record<string, string>, n: number) => Promise<void>;
}) {
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(fields.map((f) => [f.key, f.initial])));
  const [n, setN] = useState(String(number.initial));
  const save = useAction(async () => onSave(values, Number(n)));
  const num = Number(n);
  const valid = fields.every((f) => (values[f.key] ?? "").trim()) && n !== "" && num >= number.min && num <= number.max;
  return (
    <Dialog
      open
      title={title}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={save.busy} disabled={!valid} onClick={() => void save.run()}>
            Save
          </Button>
        </>
      }
    >
      {fields.map((f) => (
        <Field key={f.key} label={f.label} htmlFor={`f-${f.key}`}>
          {f.options ? (
            <select
              id={`f-${f.key}`}
              className="select"
              value={values[f.key]}
              disabled={f.locked}
              onChange={(e) => setValues((v) => ({ ...v, [f.key]: e.target.value }))}
            >
              {f.options.map((o) => (
                <option key={o} value={o}>
                  {o}
                </option>
              ))}
            </select>
          ) : (
            <input
              id={`f-${f.key}`}
              className="input"
              value={values[f.key]}
              disabled={f.locked}
              placeholder={f.placeholder}
              onChange={(e) => setValues((v) => ({ ...v, [f.key]: e.target.value }))}
            />
          )}
        </Field>
      ))}
      <Field label={number.label} htmlFor="f-number">
        <input
          id="f-number"
          className="input"
          type="number"
          min={number.min}
          max={number.max}
          value={n}
          onChange={(e) => setN(e.target.value)}
        />
      </Field>
      <ErrorBanner error={save.error} />
    </Dialog>
  );
}
