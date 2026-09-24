// Which guardrails run where. Edits change the environment's working set; publishing compiles it
// into an immutable snapshot that gateways pick up within seconds. Protected environments need a
// second admin key to approve (see Publish approvals). Rollback publishes an older version again.

import { useMemo, useState } from "react";

import { IconEdit, IconPlus, IconTrash, IconUndo } from "../components/icons";
import { useToast } from "../components/toast";
import {
  Badge,
  Button,
  Card,
  Dialog,
  EmptyState,
  ErrorBanner,
  Field,
  Json,
  KeyValue,
  Loading,
  ModeBadge,
  Mono,
  Notice,
  PageHeader,
  Segmented,
  Toolbar,
} from "../components/ui";
import { dateTime, relativeTime, scopeLabel } from "../lib/format";
import { useAction, useResource } from "../lib/hooks";
import { useQueryParam, useRoute } from "../lib/router";
import { useSession } from "../lib/session";
import {
  ENVIRONMENTS,
  type Assignment,
  type AssignmentRecord,
  type Environment,
  type GuardrailVersion,
  type PublishOutcome,
  type Snapshot,
  type Stage,
} from "../lib/types";

export function PipelinePage() {
  const { api, can, me } = useSession();
  const toast = useToast();
  const route = useRoute();
  const [envParam, setEnv] = useQueryParam(route, "env");
  const env = (ENVIRONMENTS.includes(envParam as Environment) ? envParam : "dev") as Environment;

  const working = useResource(() => api.assignments(env), [api, env]);
  const diff = useResource(() => api.diff(env), [api, env]);
  const history = useResource(() => api.snapshots(env, 20), [api, env]);
  const registry = useResource(() => api.guardrails(), [api]);

  const [editing, setEditing] = useState<Assignment | "new" | null>(null);
  const [publishing, setPublishing] = useState(false);
  const [rollbackTo, setRollbackTo] = useState<Snapshot | null>(null);
  const [removing, setRemoving] = useState<Assignment | null>(null);

  const reloadAll = async () => {
    await Promise.all([working.reload(), diff.reload(), history.reload()]);
  };

  const quick = useAction(async (id: string, patch: Partial<Assignment>) => {
    await api.patchAssignment(env, id, patch);
    await Promise.all([working.reload(), diff.reload()]);
  });
  const remove = useAction(async (a: Assignment) => {
    await api.deleteAssignment(env, a.id);
    toast("good", `Removed ${a.id} from the ${env} working set.`);
    setRemoving(null);
    await Promise.all([working.reload(), diff.reload()]);
  });

  const pending = diff.data ? diff.data.added.length + diff.data.removed.length + diff.data.changed.length : 0;
  const live = history.data?.[0];
  const protectedEnv = me.two_person_environments.includes(env);
  const canEdit = can("assignments:write");
  const rows = [...(working.data ?? [])].sort(
    (a, b) => a.assignment.order - b.assignment.order || a.assignment.id.localeCompare(b.assignment.id),
  );
  const changedIds = new Set([...(diff.data?.added ?? []), ...(diff.data?.changed ?? [])]);

  return (
    <>
      <PageHeader
        title="Pipeline"
        description="Guardrail assignments per environment. Changes stay in the working set until you publish them."
        actions={
          canEdit && (
            <Button variant="secondary" icon={<IconPlus size={14} />} onClick={() => setEditing("new")}>
              Add assignment
            </Button>
          )
        }
      />
      <Toolbar>
        <Segmented<Environment>
          label="Environment"
          value={env}
          onChange={(v) => setEnv(v === "dev" ? null : v)}
          options={ENVIRONMENTS.map((e) => ({ value: e, label: e }))}
        />
        {protectedEnv && <Badge tone="info">Two-person approval</Badge>}
      </Toolbar>
      <ErrorBanner error={working.error ?? diff.error} />
      <ErrorBanner error={quick.error} title="Could not update the assignment" />

      <div className="grid-stats">
        <div className="stat">
          <span className="stat-label">Live snapshot</span>
          <span className="stat-value mono-value">{live ? <Mono>{live.version}</Mono> : "none"}</span>
          <span className="stat-hint">
            {live ? `${live.kind} by ${live.published_by}, ${relativeTime(live.published_at)}` : "Nothing published yet"}
          </span>
        </div>
        <div className="stat">
          <span className="stat-label">Unpublished changes</span>
          <span className="stat-value">{diff.data ? pending : "—"}</span>
          <span className="stat-hint">
            {diff.data && pending > 0
              ? `${diff.data.added.length} added · ${diff.data.changed.length} changed · ${diff.data.removed.length} removed`
              : "Working set matches the live snapshot"}
          </span>
        </div>
        <div className="stat">
          <span className="stat-label">Assignments</span>
          <span className="stat-value">{working.data?.length ?? "—"}</span>
          <span className="stat-hint">
            {rows.filter((r) => r.assignment.mode === "enforce" && r.assignment.enabled).length} enforcing ·{" "}
            {rows.filter((r) => r.assignment.mode === "shadow" && r.assignment.enabled).length} in shadow
          </span>
        </div>
      </div>

      <Card
        flush
        title={`Working set · ${env}`}
        actions={
          can("publish:request") && (
            <Button variant="primary" disabled={!diff.data || pending === 0} onClick={() => setPublishing(true)}>
              {protectedEnv ? "Request publish" : "Review & publish"}
              {pending > 0 ? ` (${pending})` : ""}
            </Button>
          )
        }
      >
        {working.data === undefined ? (
          <Loading />
        ) : rows.length === 0 ? (
          <EmptyState title="No guardrails assigned">
            {canEdit ? "Add an assignment to start protecting this environment." : "Nothing runs here yet."}
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col" className="num">
                    Order
                  </th>
                  <th scope="col">Assignment</th>
                  <th scope="col">Scope</th>
                  <th scope="col">Stages</th>
                  <th scope="col">Mode</th>
                  <th scope="col">Enabled</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ assignment: a, updated_by, updated_at }) => (
                  <tr key={a.id}>
                    <td className="num">{a.order}</td>
                    <td>
                      <span className="row">
                        <strong>{a.id}</strong>
                        {changedIds.has(a.id) && <Badge tone="warning">unpublished</Badge>}
                      </span>
                      <span className="cell-sub">
                        {a.guardrail_id}@{a.guardrail_version}
                        {a.parallel_group ? ` · group ${a.parallel_group}` : ""}
                        {a.failure_mode ? ` · ${a.failure_mode}` : ""} · {updated_by}, {relativeTime(updated_at)}
                      </span>
                    </td>
                    <td>{scopeLabel(a.scope_type, a.scope_id)}</td>
                    <td>
                      {a.stages.map((s) => (
                        <span key={s} className="tag">
                          {s}
                        </span>
                      ))}
                    </td>
                    <td>
                      {canEdit ? (
                        <select
                          className="select select-auto"
                          aria-label={`Mode of ${a.id}`}
                          value={a.mode}
                          disabled={quick.busy}
                          onChange={(e) => void quick.run(a.id, { mode: e.target.value as Assignment["mode"] })}
                        >
                          <option value="shadow">shadow</option>
                          <option value="enforce">enforce</option>
                        </select>
                      ) : (
                        <ModeBadge mode={a.mode} />
                      )}
                    </td>
                    <td>
                      <label className="check">
                        <input
                          type="checkbox"
                          checked={a.enabled}
                          disabled={!canEdit || quick.busy}
                          onChange={(e) => void quick.run(a.id, { enabled: e.target.checked })}
                        />
                        <span>{a.enabled ? "on" : "off"}</span>
                      </label>
                    </td>
                    <td>
                      {canEdit && (
                        <div className="cell-actions">
                          <button type="button" className="icon-btn" aria-label={`Edit ${a.id}`} onClick={() => setEditing(a)}>
                            <IconEdit size={15} />
                          </button>
                          <button
                            type="button"
                            className="icon-btn"
                            aria-label={`Remove ${a.id}`}
                            onClick={() => setRemoving(a)}
                          >
                            <IconTrash size={15} />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card flush title="Published versions">
        {history.data === undefined ? (
          <Loading />
        ) : history.data.length === 0 ? (
          <EmptyState title="Nothing published yet" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Version</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Published</th>
                  <th scope="col">Approved by</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((s, i) => (
                  <tr key={s.id}>
                    <td>
                      <Mono>{s.version}</Mono> {i === 0 && <Badge tone="good">live</Badge>}
                      {s.rolled_back_from && <span className="cell-sub">content of {s.rolled_back_from}</span>}
                    </td>
                    <td>{s.kind}</td>
                    <td>
                      {s.published_by}
                      <span className="cell-sub">{dateTime(s.published_at)}</span>
                    </td>
                    <td>{s.approved_by ?? "—"}</td>
                    <td>
                      {i > 0 && can("publish:request") && (
                        <div className="cell-actions">
                          <Button size="sm" icon={<IconUndo size={14} />} onClick={() => setRollbackTo(s)}>
                            Roll back to this
                          </Button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {editing && (
        <AssignmentDialog
          env={env}
          initial={editing === "new" ? null : editing}
          registry={registry.data ?? []}
          existingIds={rows.map((r) => r.assignment.id)}
          onClose={() => setEditing(null)}
          onSaved={async (a) => {
            setEditing(null);
            toast("good", `Saved ${a.id} to the ${env} working set.`);
            await Promise.all([working.reload(), diff.reload()]);
          }}
        />
      )}
      <PublishDialog
        open={publishing}
        env={env}
        protectedEnv={protectedEnv}
        working={rows}
        onClose={() => setPublishing(false)}
        onDone={reloadAll}
      />
      {rollbackTo && (
        <RollbackDialog
          env={env}
          snapshot={rollbackTo}
          protectedEnv={protectedEnv}
          onClose={() => setRollbackTo(null)}
          onDone={reloadAll}
        />
      )}
      <Dialog
        open={removing !== null}
        title={`Remove ${removing?.id ?? ""}?`}
        onClose={() => setRemoving(null)}
        footer={
          <>
            <Button onClick={() => setRemoving(null)}>Cancel</Button>
            <Button variant="danger" busy={remove.busy} onClick={() => removing && void remove.run(removing)}>
              Remove
            </Button>
          </>
        }
      >
        <p>
          The assignment leaves the {env} working set. Gateways keep running it until you publish. To pause it instead,
          turn it off.
        </p>
        <ErrorBanner error={remove.error} />
      </Dialog>
    </>
  );
}

// ---- add / edit ------------------------------------------------------------------------------------

function AssignmentDialog({
  env,
  initial,
  registry,
  existingIds,
  onClose,
  onSaved,
}: {
  env: Environment;
  initial: Assignment | null;
  registry: GuardrailVersion[];
  existingIds: string[];
  onClose: () => void;
  onSaved: (a: AssignmentRecord["assignment"]) => Promise<void>;
}) {
  const { api, me } = useSession();
  const usable = registry.filter((v) => v.status !== "deprecated" || (initial && v.guardrail_id === initial.guardrail_id));
  const [id, setId] = useState(initial?.id ?? "");
  const [guardrail, setGuardrail] = useState(
    initial ? `${initial.guardrail_id}@${initial.guardrail_version}` : usable[0] ? `${usable[0].guardrail_id}@${usable[0].version}` : "",
  );
  const [scopeType, setScopeType] = useState<Assignment["scope_type"]>(
    initial?.scope_type ?? (me.platform ? "global" : "tenant"),
  );
  const [scopeId, setScopeId] = useState(initial?.scope_id ?? (me.platform ? "" : me.tenant_id ?? ""));
  const [stages, setStages] = useState<Stage[]>(initial?.stages ?? []);
  const [order, setOrder] = useState(String(initial?.order ?? 100));
  const [group, setGroup] = useState(initial?.parallel_group ?? "");
  const [mode, setMode] = useState<Assignment["mode"]>(initial?.mode ?? "shadow");
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [failure, setFailure] = useState(initial?.failure_mode ?? "");
  const [timeout, setTimeoutMs] = useState(initial?.timeout_ms ? String(initial.timeout_ms) : "");
  const [config, setConfig] = useState(JSON.stringify(initial?.config ?? {}, null, 2));
  const [localError, setLocalError] = useState<string | null>(null);

  const selected = useMemo(() => usable.find((v) => `${v.guardrail_id}@${v.version}` === guardrail), [usable, guardrail]);
  const supported = selected?.manifest.stages ?? [];

  const save = useAction(async () => {
    setLocalError(null);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(config || "{}") as Record<string, unknown>;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    } catch {
      setLocalError("Config must be a JSON object.");
      return;
    }
    if (!initial && existingIds.includes(id.trim())) {
      setLocalError(`An assignment called ${id.trim()} already exists in ${env}.`);
      return;
    }
    const [gid, version] = guardrail.split("@") as [string, string];
    const body: Partial<Assignment> & { id: string } = {
      id: id.trim(),
      guardrail_id: gid,
      guardrail_version: version,
      scope_type: scopeType,
      scope_id: scopeType === "global" ? null : scopeId.trim(),
      stages,
      order: Number(order),
      parallel_group: group.trim() || null,
      mode,
      enabled,
      failure_mode: (failure || null) as Assignment["failure_mode"],
      timeout_ms: timeout ? Number(timeout) : null,
      config: parsed,
    };
    const rec = await api.putAssignment(env, body);
    await onSaved(rec.assignment);
  });

  const toggleStage = (s: Stage) => setStages((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));

  return (
    <Dialog
      open
      wide
      title={initial ? `Edit ${initial.id} · ${env}` : `Add an assignment · ${env}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            busy={save.busy}
            disabled={!id.trim() || !guardrail || stages.length === 0}
            onClick={() => void save.run()}
          >
            Save to working set
          </Button>
        </>
      }
    >
      <div className="form-row">
        <Field label="Assignment ID" htmlFor="a-id" hint="Letters, digits and . _ : / -">
          <input id="a-id" className="input" value={id} disabled={!!initial} onChange={(e) => setId(e.target.value)} />
        </Field>
        <Field label="Guardrail version" htmlFor="a-g">
          <select
            id="a-g"
            className="select"
            value={guardrail}
            onChange={(e) => {
              setGuardrail(e.target.value);
              setStages([]);
            }}
          >
            {usable.map((v) => (
              <option key={`${v.guardrail_id}@${v.version}`} value={`${v.guardrail_id}@${v.version}`}>
                {v.guardrail_id}@{v.version}
                {v.status === "deprecated" ? " (deprecated)" : ""}
              </option>
            ))}
          </select>
        </Field>
      </div>
      {selected && <p className="field-hint">{selected.manifest.description}</p>}
      <Field label="Stages">
        <div>
          {supported.map((s) => (
            <label key={s} className="check">
              <input type="checkbox" checked={stages.includes(s)} onChange={() => toggleStage(s)} />
              {s}
            </label>
          ))}
        </div>
      </Field>
      <div className="form-row">
        <Field label="Scope" htmlFor="a-scope">
          <select
            id="a-scope"
            className="select"
            value={scopeType}
            onChange={(e) => setScopeType(e.target.value as Assignment["scope_type"])}
          >
            {me.platform && <option value="global">global</option>}
            <option value="tenant">tenant</option>
            <option value="agent">agent</option>
          </select>
        </Field>
        {scopeType !== "global" && (
          <Field label={scopeType === "agent" ? "Tenant/agent" : "Tenant"} htmlFor="a-scope-id">
            <input
              id="a-scope-id"
              className="input"
              value={scopeId}
              placeholder={scopeType === "agent" ? "acme/support-bot" : "acme"}
              onChange={(e) => setScopeId(e.target.value)}
            />
          </Field>
        )}
        <Field label="Order" htmlFor="a-order" hint="Lower runs first">
          <input id="a-order" className="input" type="number" value={order} onChange={(e) => setOrder(e.target.value)} />
        </Field>
        <Field label="Parallel group" htmlFor="a-group" hint="Optional">
          <input id="a-group" className="input" value={group} onChange={(e) => setGroup(e.target.value)} />
        </Field>
      </div>
      <div className="form-row">
        <Field label="Mode" htmlFor="a-mode" hint="Shadow runs and is audited but never changes the outcome">
          <select id="a-mode" className="select" value={mode} onChange={(e) => setMode(e.target.value as Assignment["mode"])}>
            <option value="shadow">shadow</option>
            <option value="enforce">enforce</option>
          </select>
        </Field>
        <Field label="On error" htmlFor="a-fail" hint={`Manifest default: ${selected?.manifest.failure_mode ?? "—"}`}>
          <select id="a-fail" className="select" value={failure} onChange={(e) => setFailure(e.target.value)}>
            <option value="">manifest default</option>
            <option value="fail_closed">fail_closed (block)</option>
            <option value="fail_open">fail_open (allow)</option>
          </select>
        </Field>
        <Field label="Timeout (ms)" htmlFor="a-timeout" hint="Optional">
          <input
            id="a-timeout"
            className="input"
            type="number"
            min={1}
            max={30000}
            value={timeout}
            onChange={(e) => setTimeoutMs(e.target.value)}
          />
        </Field>
        <Field label="Enabled" htmlFor="a-enabled">
          <label className="check">
            <input id="a-enabled" type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> on
          </label>
        </Field>
      </div>
      <Field label="Config (JSON)" htmlFor="a-config" hint="Checked against the guardrail's config schema when you publish.">
        <textarea id="a-config" className="textarea" rows={8} value={config} onChange={(e) => setConfig(e.target.value)} />
      </Field>
      {selected && (
        <details>
          <summary className="muted">Config schema for {selected.guardrail_id}@{selected.version}</summary>
          <Json value={selected.manifest.config_schema} maxHeight="sm" />
        </details>
      )}
      {localError && <Notice tone="warning">{localError}</Notice>}
      <ErrorBanner error={save.error} title="The assignment was not saved" />
    </Dialog>
  );
}

// ---- publish ---------------------------------------------------------------------------------------

function PublishDialog({
  open,
  env,
  protectedEnv,
  working,
  onClose,
  onDone,
}: {
  open: boolean;
  env: Environment;
  protectedEnv: boolean;
  working: AssignmentRecord[];
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const { api } = useSession();
  const toast = useToast();
  const diff = useResource(() => (open ? api.diff(env) : Promise.resolve(undefined)), [api, env, open]);
  const [note, setNote] = useState("");
  const [force, setForce] = useState(false);
  const [outcome, setOutcome] = useState<PublishOutcome | null>(null);

  const publish = useAction(async () => {
    const o = await api.publish(env, note.trim(), force);
    setOutcome(o);
    if (o.status === "published") toast("good", `Published ${o.snapshot?.version ?? ""} to ${env}.`);
    if (o.status === "pending_approval") toast("good", "Publish requested. A second admin must approve it.");
    await onDone();
    return o;
  });

  const close = () => {
    setOutcome(null);
    setNote("");
    setForce(false);
    publish.clearError();
    onClose();
  };
  const d = diff.data;
  const ids = d ? [...d.added, ...d.changed, ...d.removed] : [];

  return (
    <Dialog
      open={open}
      wide
      title={protectedEnv ? `Request publish to ${env}` : `Publish to ${env}`}
      onClose={close}
      footer={
        outcome ? (
          <Button variant="primary" onClick={close}>
            Done
          </Button>
        ) : (
          <>
            <Button onClick={close}>Cancel</Button>
            <Button variant="primary" busy={publish.busy} disabled={!d || ids.length === 0} onClick={() => void publish.run()}>
              {protectedEnv ? "Request approval" : "Publish"}
            </Button>
          </>
        )
      }
    >
      {outcome ? (
        <div className="stack">
          {outcome.status === "published" && (
            <Notice tone="good">
              <strong>Published {outcome.snapshot?.version}.</strong> Gateways in {env} load it within seconds.
            </Notice>
          )}
          {outcome.status === "pending_approval" && (
            <Notice tone="info">
              <strong>Waiting for approval.</strong> Another admin key must approve request{" "}
              <Mono>{outcome.request?.id}</Mono> under Publish approvals.
            </Notice>
          )}
          {outcome.status === "unchanged" && <Notice>Nothing changed: the live snapshot already matches.</Notice>}
          {outcome.warnings.map((w, i) => (
            <Notice key={i} tone="warning">
              {w}
            </Notice>
          ))}
        </div>
      ) : (
        <div className="stack">
          {diff.error && <ErrorBanner error={diff.error} />}
          {!d ? (
            <Loading />
          ) : ids.length === 0 ? (
            <Notice>The working set matches the live snapshot.</Notice>
          ) : (
            <>
              <p>
                Compared with <Mono>{d.base_version ?? "nothing published"}</Mono>:
              </p>
              {ids.map((id) => (
                <DiffEntry
                  key={id}
                  id={id}
                  kind={d.added.includes(id) ? "added" : d.removed.includes(id) ? "removed" : "changed"}
                  live={d.details?.[id]?.live ?? null}
                  working={d.details?.[id]?.working ?? working.find((w) => w.assignment.id === id)?.assignment ?? null}
                />
              ))}
            </>
          )}
          <Field label="Note" htmlFor="pub-note" hint="Shown in the history and to the approver.">
            <input id="pub-note" className="input" value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} />
          </Field>
          <label className="check">
            <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} />
            Publish even if a live gateway does not have a guardrail version installed yet (warn instead of refuse)
          </label>
          <ErrorBanner error={publish.error} title="Not published" />
        </div>
      )}
    </Dialog>
  );
}

function show(value: unknown): string {
  if (value === null || value === undefined) return "—";
  return typeof value === "string" ? value : JSON.stringify(value);
}

export function DiffEntry({
  id,
  kind,
  live,
  working,
}: {
  id: string;
  kind: "added" | "removed" | "changed";
  live: Assignment | null;
  working: Assignment | null;
}) {
  const tone = kind === "added" ? "good" : kind === "removed" ? "critical" : "warning";
  const current = working ?? live;
  const changedKeys =
    kind === "changed" && live && working
      ? (Object.keys({ ...live, ...working }) as (keyof Assignment)[]).filter(
          (k) => JSON.stringify(live[k]) !== JSON.stringify(working[k]),
        )
      : [];
  return (
    <div className="diff-entry">
      <div className="row">
        <Badge tone={tone}>{kind}</Badge>
        <strong>{id}</strong>
        {current && (
          <span className="muted">
            {current.guardrail_id}@{current.guardrail_version} · {scopeLabel(current.scope_type, current.scope_id)} ·{" "}
            {current.mode}
          </span>
        )}
      </div>
      {changedKeys.length > 0 && (
        <table className="table table-compact diff-table">
          <thead>
            <tr>
              <th scope="col">Field</th>
              <th scope="col">Live</th>
              <th scope="col">After publish</th>
            </tr>
          </thead>
          <tbody>
            {changedKeys.map((k) => (
              <tr key={k}>
                <td>
                  <Mono>{k}</Mono>
                </td>
                <td className="diff-old">{show(live?.[k])}</td>
                <td className="diff-new">{show(working?.[k])}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <details>
        <summary className="muted">Full assignment</summary>
        <div className="diff-grid">
          <div className="diff-side">
            <h3>Live</h3>
            {live ? <Json value={live} maxHeight="sm" /> : <p className="muted">—</p>}
          </div>
          <div className="diff-side">
            <h3>After publish</h3>
            {working ? <Json value={working} maxHeight="sm" /> : <p className="muted">removed</p>}
          </div>
        </div>
      </details>
    </div>
  );
}

function RollbackDialog({
  env,
  snapshot,
  protectedEnv,
  onClose,
  onDone,
}: {
  env: Environment;
  snapshot: Snapshot;
  protectedEnv: boolean;
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const { api } = useSession();
  const toast = useToast();
  const [note, setNote] = useState("");
  const [outcome, setOutcome] = useState<PublishOutcome | null>(null);
  const rollback = useAction(async () => {
    const o = await api.rollback(env, snapshot.version, note.trim());
    setOutcome(o);
    toast("good", o.status === "pending_approval" ? "Rollback requested." : `Rolled back ${env}.`);
    await onDone();
  });
  return (
    <Dialog
      open
      title={`Roll back ${env} to ${snapshot.version}?`}
      onClose={onClose}
      footer={
        outcome ? (
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        ) : (
          <>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="danger" busy={rollback.busy} onClick={() => void rollback.run()}>
              {protectedEnv ? "Request rollback" : "Roll back"}
            </Button>
          </>
        )
      }
    >
      {outcome ? (
        <Notice tone={outcome.status === "pending_approval" ? "info" : "good"}>
          {outcome.status === "pending_approval"
            ? "A second admin must approve the rollback under Publish approvals."
            : `Published ${outcome.snapshot?.version} with the content of ${snapshot.version}.`}
        </Notice>
      ) : (
        <div className="stack">
          <KeyValue
            items={[
              ["Version", <Mono key="v">{snapshot.version}</Mono>],
              ["Originally published", `${dateTime(snapshot.published_at)} by ${snapshot.published_by}`],
            ]}
          />
          <p>
            This publishes a new version with the same content, and resets the working set to it so your next publish
            doesn't undo the rollback.
          </p>
          <Field label="Reason" htmlFor="rb-note">
            <input id="rb-note" className="input" value={note} onChange={(e) => setNote(e.target.value)} />
          </Field>
          <ErrorBanner error={rollback.error} title="Rollback failed" />
        </div>
      )}
    </Dialog>
  );
}
