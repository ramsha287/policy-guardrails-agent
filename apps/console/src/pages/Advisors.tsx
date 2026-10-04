// Advisor pilot: how the configured advisors are answering, and the per-tenant data policy that
// decides whether a hosted advisor may see a request. Advisors can only add risk or ask for
// verification; they never permit. Read-only except the data policy (catalog:write).

import { useState } from "react";

import { useToast } from "../components/toast";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  Field,
  Loading,
  Notice,
  PageHeader,
  Segmented,
  Toolbar,
} from "../components/ui";
import { agreementRate, labelShare, normaliseClasses, pilotNote, sameClasses } from "../lib/advisors";
import { compact, percent } from "../lib/format";
import { useAction, useResource } from "../lib/hooks";
import { useQueryParam, useRoute } from "../lib/router";
import { useSession } from "../lib/session";
import { DATA_CLASSES, type AdvisorSummary, type DataClass, type Environment, ENVIRONMENTS } from "../lib/types";

const RANGES = [
  { value: "168", label: "7 days" },
  { value: "720", label: "30 days" },
  { value: "2160", label: "90 days" },
];

export function AdvisorsPage() {
  const { api, me } = useSession();
  const route = useRoute();
  const [hoursParam, setHours] = useQueryParam(route, "hours");
  const [envParam, setEnv] = useQueryParam(route, "env");
  const [tenantParam, setTenant] = useQueryParam(route, "tenant");
  const effectiveTenant = tenantParam || me.tenant_id || "";
  const hours = Number(hoursParam || "168");
  const env = (ENVIRONMENTS.includes(envParam as Environment) ? envParam : "") as Environment | "";
  const data = useResource(
    () => api.advisorAnalytics({ hours, environment: env, tenant_id: tenantParam || undefined }),
    [api, hours, env, tenantParam],
    60_000,
  );

  return (
    <>
      <PageHeader
        title="Advisors"
        description="Optional classifiers asked only for elevated and high risk. They can add capped risk or ask for a person to confirm — never permit. Pilot them in shadow mode, then enforce."
      />
      <Toolbar>
        <Segmented label="Time range" value={String(hours)} onChange={(v) => setHours(v === "168" ? null : v)} options={RANGES} />
        <select className="select select-auto" aria-label="Environment" value={env} onChange={(e) => setEnv(e.target.value || null)}>
          <option value="">All environments</option>
          {ENVIRONMENTS.map((e) => (
            <option key={e}>{e}</option>
          ))}
        </select>
        {me.platform && <TenantSelect value={tenantParam} onChange={setTenant} />}
      </Toolbar>
      <ErrorBanner error={data.error} />
      {effectiveTenant && <DataPolicyCard tenant={effectiveTenant} />}
      {data.data === undefined ? (
        data.error ? null : <Loading />
      ) : data.data.advisors.length === 0 ? (
        <Card>
          <EmptyState title="No advisor answers in this window">
            Configure advisors on the gateway (<code>ADVISORS_JSON</code>) and run them in shadow mode. Answers are
            recorded with each decision and summarised here.
          </EmptyState>
        </Card>
      ) : (
        <div className={data.loading ? "stack refetching" : "stack"}>
          <Card flush title="Advisors">
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Advisor</th>
                    <th scope="col">Mode</th>
                    <th scope="col" className="num">
                      Questions
                    </th>
                    <th scope="col" className="num">
                      Flagged
                    </th>
                    <th scope="col" className="num">
                      No signal
                    </th>
                    <th scope="col" className="num">
                      Agreement
                    </th>
                    <th scope="col">Pilot</th>
                  </tr>
                </thead>
                <tbody>
                  {data.data.advisors.map((a) => (
                    <AdvisorRow key={a.advisor} a={a} />
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}
    </>
  );
}

function TenantSelect({ value, onChange }: { value: string; onChange: (v: string | null) => void }) {
  const { api } = useSession();
  const tenants = useResource(() => api.tenants(), [api]);
  return (
    <select className="select select-auto" aria-label="Tenant" value={value} onChange={(e) => onChange(e.target.value || null)}>
      <option value="">All tenants</option>
      {(tenants.data ?? []).map((t) => (
        <option key={t.id} value={t.id}>
          {t.id}
        </option>
      ))}
    </select>
  );
}


function AdvisorRow({ a }: { a: AdvisorSummary }) {
  const note = pilotNote(a);
  const flagged = labelShare(a, "suspicious") + labelShare(a, "malicious");
  const agree = agreementRate(a);
  return (
    <tr>
      <td>
        {a.advisor}
        <span className="cell-sub">{a.provider}</span>
      </td>
      <td>
        <Badge tone={a.mode === "enforce" ? "warning" : "neutral"}>{a.mode}</Badge>
      </td>
      <td className="num">{compact(a.questions)}</td>
      <td className="num">{percent(flagged)}</td>
      <td className="num">{percent(a.no_signal_rate)}</td>
      <td className="num">{agree === null ? "—" : percent(agree)}</td>
      <td>
        <Badge tone={note.tone}>{note.text}</Badge>
      </td>
    </tr>
  );
}

function DataPolicyCard({ tenant }: { tenant: string }) {
  const { api, can } = useSession();
  const toast = useToast();
  const info = useResource(() => api.tenants(), [api, tenant]);
  const current = info.data?.find((t) => t.id === tenant);
  const [draft, setDraft] = useState<DataClass[] | null>(null);
  const classes = draft ?? normaliseClasses(current?.advisor_data_classes ?? []);
  const editable = can("catalog:write");

  const save = useAction(async () => {
    const saved = await api.setAdvisorPolicy(tenant, classes);
    setDraft(null);
    await info.reload();
    toast("good", saved.advisor_data_classes?.length ? "Hosted advisors updated." : "Hosted advisors turned off.");
  });

  if (info.data !== undefined && current === undefined) return null;
  const dirty = draft !== null && !sameClasses(current?.advisor_data_classes, classes);
  return (
    <Card title="Hosted advisor data policy">
      <p className="muted">
        A hosted advisor (a vendor classifier or an LLM judge) only sees a request when this tenant allows its data
        class, and every sensitive class the session already holds. Off by default; local advisors never leave the
        gateway and ignore this.
      </p>
      <Field label="Data classes hosted advisors may see">
        <div className="row">
          {DATA_CLASSES.map((c) => (
            <label key={c} className="check">
              <input
                type="checkbox"
                disabled={!editable || save.busy}
                checked={classes.includes(c)}
                onChange={(e) =>
                  setDraft(
                    normaliseClasses(e.target.checked ? [...classes, c] : classes.filter((x) => x !== c)),
                  )
                }
              />{" "}
              {c}
            </label>
          ))}
        </div>
      </Field>
      {classes.length === 0 ? (
        <Notice tone="info">Hosted advisors are off for this tenant. Local advisors still run.</Notice>
      ) : (
        <Notice tone="warning">
          Hosted advisors may see {classes.join(", ")} data for this tenant. This sends derived features (never request
          text) to the advisor's endpoint.
        </Notice>
      )}
      <ErrorBanner error={save.error ?? info.error} />
      {editable && (
        <div className="row">
          <Button variant="primary" busy={save.busy} disabled={!dirty} onClick={() => void save.run()}>
            Save policy
          </Button>
          {dirty && (
            <Button variant="ghost" onClick={() => setDraft(null)}>
              Reset
            </Button>
          )}
        </div>
      )}
    </Card>
  );
}
