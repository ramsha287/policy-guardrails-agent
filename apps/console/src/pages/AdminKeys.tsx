// Admin keys for the control plane (and this console). Platform keys act on everything; tenant keys
// only on their tenant. Publishing and the registry are platform-only.

import { useState } from "react";

import { IconPlus } from "../components/icons";
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
} from "../components/ui";
import { dateTime } from "../lib/format";
import { useAction, useResource } from "../lib/hooks";
import { useSession } from "../lib/session";
import type { AdminKey } from "../lib/types";

export const ROLE_HELP: Record<string, string> = {
  viewer: "Read everything in its scope",
  reviewer: "Approve or reject held requests (redacted preview only)",
  "reviewer-raw": "Reviewer who can also open the raw held payload",
  editor: "Change the catalog and assignments, request publishes",
  admin: "Everything, including approvals, the registry and admin keys",
};

export function AdminKeysPage() {
  const { api, me } = useSession();
  const toast = useToast();
  const keys = useResource(() => api.adminKeys(), [api]);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<(AdminKey & { key: string }) | null>(null);
  const [revoking, setRevoking] = useState<AdminKey | null>(null);
  const revoke = useAction(async (k: AdminKey) => {
    await api.revokeAdminKey(k.id);
    toast("good", `Revoked ${k.name}.`);
    setRevoking(null);
    await keys.reload();
  });
  return (
    <>
      <PageHeader
        title="Admin keys"
        description="Keys for this console and the control-plane API. Roles decide what a key can do."
        actions={
          <Button icon={<IconPlus size={14} />} onClick={() => setCreating(true)}>
            New admin key
          </Button>
        }
      />
      <ErrorBanner error={keys.error} />
      <Card flush>
        {keys.data === undefined ? (
          <Loading />
        ) : keys.data.length === 0 ? (
          <EmptyState title="No admin keys" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Roles</th>
                  <th scope="col">Scope</th>
                  <th scope="col">Status</th>
                  <th scope="col">Created</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {keys.data.map((k) => (
                  <tr key={k.id}>
                    <td>
                      {k.name} {k.id === me.key_id && <Badge tone="info">you</Badge>}
                      <span className="cell-sub">
                        <Mono>{k.prefix}…</Mono>
                      </span>
                    </td>
                    <td>
                      {k.roles.map((r) => (
                        <span key={r} className="tag" title={ROLE_HELP[r]}>
                          {r}
                        </span>
                      ))}
                    </td>
                    <td>{k.tenant_id ? `tenant ${k.tenant_id}` : "platform"}</td>
                    <td>{k.is_active ? <Badge tone="good">active</Badge> : <Badge tone="critical">revoked</Badge>}</td>
                    <td>{dateTime(k.created_at)}</td>
                    <td>
                      {k.is_active && k.id !== me.key_id && (
                        <div className="cell-actions">
                          <Button size="sm" variant="ghost" onClick={() => setRevoking(k)}>
                            Revoke
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
      {creating && (
        <CreateAdminKey
          onClose={() => setCreating(false)}
          onDone={async (k) => {
            setCreating(false);
            setCreated(k);
            await keys.reload();
          }}
        />
      )}
      <Dialog
        open={created !== null}
        title="Copy the new admin key"
        onClose={() => setCreated(null)}
        footer={
          <Button variant="primary" onClick={() => setCreated(null)}>
            I've stored it
          </Button>
        }
      >
        {created && (
          <div className="stack">
            <Notice tone="warning">This is the only time the key is shown.</Notice>
            <div className="secret">
              <span>{created.key}</span>
              <CopyButton text={created.key} />
            </div>
          </div>
        )}
      </Dialog>
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
        <p>The key stops working immediately, including any console session using it.</p>
        <ErrorBanner error={revoke.error} />
      </Dialog>
    </>
  );
}

function CreateAdminKey({
  onClose,
  onDone,
}: {
  onClose: () => void;
  onDone: (k: AdminKey & { key: string }) => Promise<void>;
}) {
  const { api, me } = useSession();
  const tenants = useResource(() => api.tenants(), [api]);
  const [name, setName] = useState("");
  const [roles, setRoles] = useState<string[]>(["reviewer"]);
  const [tenant, setTenant] = useState(me.tenant_id ?? "");
  const create = useAction(async () =>
    onDone(await api.createAdminKey({ name: name.trim(), roles, tenant_id: tenant || null })),
  );
  return (
    <Dialog
      open
      title="New admin key"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={create.busy} disabled={!name.trim() || roles.length === 0} onClick={() => void create.run()}>
            Create key
          </Button>
        </>
      }
    >
      <Field label="Name" htmlFor="ak-name" hint="Who or what uses it, e.g. alice or ci-publisher">
        <input id="ak-name" className="input" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Roles">
        <div className="stack stack-tight">
          {Object.entries(ROLE_HELP).map(([role, help]) => (
            <label key={role} className="check">
              <input
                type="checkbox"
                checked={roles.includes(role)}
                onChange={() => setRoles((cur) => (cur.includes(role) ? cur.filter((r) => r !== role) : [...cur, role]))}
              />
              <span>
                <strong>{role}</strong> <span className="muted">{help}</span>
              </span>
            </label>
          ))}
        </div>
      </Field>
      <Field label="Scope" htmlFor="ak-tenant" hint="A tenant key only sees and changes its own tenant.">
        <select
          id="ak-tenant"
          className="select"
          value={tenant}
          disabled={!me.platform}
          onChange={(e) => setTenant(e.target.value)}
        >
          {me.platform && <option value="">platform (all tenants)</option>}
          {(tenants.data ?? []).map((t) => (
            <option key={t.id} value={t.id}>
              tenant {t.id}
            </option>
          ))}
        </select>
      </Field>
      <ErrorBanner error={create.error} />
    </Dialog>
  );
}
