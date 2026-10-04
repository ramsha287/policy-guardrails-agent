// Tenant choice for tenant-scoped screens, kept in the URL (?tenant=) so links and reloads keep it.
// Tenant keys only ever see their own tenant, so the picker hides itself for them.

import { useId } from "react";

import { useResource } from "../lib/hooks";
import { useQueryParam, useRoute } from "../lib/router";
import { useSession } from "../lib/session";
import type { Tenant } from "../lib/types";

export function useTenantChoice(): {
  tenants: Tenant[] | undefined;
  tenant: Tenant | undefined;
  setTenant: (id: string) => void;
  error: Error | undefined;
} {
  const { api } = useSession();
  const route = useRoute();
  const [param, setParam] = useQueryParam(route, "tenant");
  const tenants = useResource(() => api.tenants(), [api]);
  const list = tenants.data;
  const tenant = list?.find((t) => t.id === param) ?? list?.[0];
  return { tenants: list, tenant, setTenant: (id) => setParam(id), error: tenants.error };
}

export function TenantPicker({
  tenants,
  tenant,
  onChange,
}: {
  tenants: Tenant[] | undefined;
  tenant: Tenant | undefined;
  onChange: (id: string) => void;
}) {
  const id = useId();
  if (!tenants || tenants.length < 2) return null;
  return (
    <label className="row" htmlFor={id}>
      <span className="muted">Tenant</span>
      <select id={id} className="select select-auto" value={tenant?.id ?? ""} onChange={(e) => onChange(e.target.value)}>
        {tenants.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name} ({t.id})
          </option>
        ))}
      </select>
    </label>
  );
}
