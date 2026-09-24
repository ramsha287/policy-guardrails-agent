// Guardrail registry: every version a gateway reported or an admin registered, with its manifest.
// A version can only be assigned if it is registered, not deprecated, and installed on the gateways.

import { useState, type ChangeEvent } from "react";

import { IconPlus } from "../components/icons";
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
  Mono,
  PageHeader,
} from "../components/ui";
import { dateTime } from "../lib/format";
import { useAction, useResource } from "../lib/hooks";
import { useSession } from "../lib/session";
import { ENVIRONMENTS, type Gateway, type GuardrailVersion } from "../lib/types";

export function GuardrailsPage() {
  const { api, can } = useSession();
  const toast = useToast();
  const versions = useResource(() => api.guardrails(), [api]);
  const fleet = useResource(
    () => Promise.all(ENVIRONMENTS.map((e) => api.gateways(e).catch(() => [] as Gateway[]))).then((x) => x.flat()),
    [api],
  );
  const [registering, setRegistering] = useState(false);
  const [viewing, setViewing] = useState<GuardrailVersion | null>(null);
  const [deprecating, setDeprecating] = useState<GuardrailVersion | null>(null);

  const deprecate = useAction(async (v: GuardrailVersion) => {
    await api.deprecate(v.guardrail_id, v.version);
    toast("good", `${v.guardrail_id}@${v.version} is deprecated.`);
    setDeprecating(null);
    await versions.reload();
  });

  const live = (fleet.data ?? []).filter((g) => g.live);
  const installedOn = (v: GuardrailVersion) => live.filter((g) => g.installed.includes(`${v.guardrail_id}@${v.version}`));

  const sorted = [...(versions.data ?? [])].sort(
    (a, b) => a.guardrail_id.localeCompare(b.guardrail_id) || b.version.localeCompare(a.version, undefined, { numeric: true }),
  );

  return (
    <>
      <PageHeader
        title="Guardrails"
        description="Registered guardrail versions. Gateways report what they have installed; remote guardrails can be registered here."
        actions={
          can("registry:write") && (
            <Button icon={<IconPlus size={14} />} onClick={() => setRegistering(true)}>
              Register a version
            </Button>
          )
        }
      />
      <ErrorBanner error={versions.error} />
      <Card flush>
        {versions.data === undefined ? (
          <Loading />
        ) : sorted.length === 0 ? (
          <EmptyState title="No guardrails registered">Gateways register their installed guardrails when they start.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Guardrail</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Stages</th>
                  <th scope="col">On error</th>
                  <th scope="col">Live gateways</th>
                  <th scope="col">Status</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((v) => {
                  const on = installedOn(v);
                  return (
                    <tr key={`${v.guardrail_id}@${v.version}`}>
                      <td>
                        <button type="button" className="link-btn" onClick={() => setViewing(v)}>
                          <strong>{v.guardrail_id}</strong>@{v.version}
                        </button>
                        <span className="cell-sub">{v.manifest.owner}</span>
                      </td>
                      <td>{v.manifest.kind}</td>
                      <td>
                        {v.manifest.stages.map((s) => (
                          <span key={s} className="tag">
                            {s}
                          </span>
                        ))}
                      </td>
                      <td>{v.manifest.failure_mode}</td>
                      <td>
                        {fleet.data === undefined ? "…" : `${on.length} of ${live.length}`}
                        {on.length > 0 && (
                          <span className="cell-sub">{[...new Set(on.map((g) => g.environment))].join(", ")}</span>
                        )}
                      </td>
                      <td>
                        {v.status === "deprecated" ? <Badge tone="neutral">deprecated</Badge> : <Badge tone="good">validated</Badge>}
                        <span className="cell-sub">from {v.source}</span>
                      </td>
                      <td>
                        {can("registry:write") && v.status !== "deprecated" && (
                          <div className="cell-actions">
                            <Button size="sm" variant="ghost" onClick={() => setDeprecating(v)}>
                              Deprecate
                            </Button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Dialog open={viewing !== null} wide title={viewing ? `${viewing.guardrail_id}@${viewing.version}` : ""} onClose={() => setViewing(null)}>
        {viewing && (
          <div className="stack">
            <p>{viewing.manifest.description}</p>
            <KeyValue
              items={[
                ["Owner", viewing.manifest.owner],
                ["Data handling", viewing.manifest.data_handling],
                ["Decisions", viewing.manifest.decisions_emitted.join(", ")],
                ["Latency budget", viewing.manifest.latency_budget_ms ? `${viewing.manifest.latency_budget_ms} ms` : "—"],
                ["Parallel safe", viewing.manifest.capabilities?.parallel_safe ? "yes" : "no"],
                ["Registered", `${dateTime(viewing.created_at)} (${viewing.source})`],
                ["Conformance", viewing.conformance_report ? (viewing.conformance_report.passed ? "passed" : "failed") : "no report"],
              ]}
            />
            <p className="field-label">Manifest</p>
            <Json value={viewing.manifest} maxHeight="md" />
          </div>
        )}
      </Dialog>

      <Dialog
        open={deprecating !== null}
        title={`Deprecate ${deprecating?.guardrail_id ?? ""}@${deprecating?.version ?? ""}?`}
        onClose={() => setDeprecating(null)}
        footer={
          <>
            <Button onClick={() => setDeprecating(null)}>Cancel</Button>
            <Button variant="danger" busy={deprecate.busy} onClick={() => deprecating && void deprecate.run(deprecating)}>
              Deprecate
            </Button>
          </>
        }
      >
        <p>
          Snapshots that already use it keep working, but new publishes that use it are refused. This can't be undone;
          register a new version instead.
        </p>
        <ErrorBanner error={deprecate.error} />
      </Dialog>

      {registering && (
        <RegisterDialog
          onClose={() => setRegistering(false)}
          onDone={async (v) => {
            setRegistering(false);
            toast("good", `Registered ${v.guardrail_id}@${v.version}.`);
            await versions.reload();
          }}
        />
      )}
    </>
  );
}

function RegisterDialog({ onClose, onDone }: { onClose: () => void; onDone: (v: GuardrailVersion) => Promise<void> }) {
  const { api } = useSession();
  const [text, setText] = useState("");
  const register = useAction(async () => {
    const v = await api.registerGuardrail(text);
    await onDone(v);
  });
  const onFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 200_000) return;
    void file.text().then(setText);
  };
  return (
    <Dialog
      open
      wide
      title="Register a guardrail version"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={register.busy} disabled={!text.trim()} onClick={() => void register.run()}>
            Register
          </Button>
        </>
      }
    >
      <p className="page-description">
        Paste the guardrail's <Mono>guardrail.yaml</Mono>. The manifest is validated, and an id@version that already exists
        must be identical.
      </p>
      <Field label="Manifest file" htmlFor="manifest-file">
        <input id="manifest-file" type="file" accept=".yaml,.yml,.json" onChange={onFile} />
      </Field>
      <Field label="guardrail.yaml" htmlFor="manifest-text">
        <textarea
          id="manifest-text"
          className="textarea"
          rows={16}
          spellCheck={false}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={"id: prompt-injection\nversion: 1.0.0\nkind: remote\nstages: [input]\n…"}
        />
      </Field>
      <ErrorBanner error={register.error} title="Not registered" />
    </Dialog>
  );
}
