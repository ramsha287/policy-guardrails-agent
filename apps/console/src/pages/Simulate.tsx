// Dry-run a request through the working set (a draft) or the live snapshot on a real gateway.
// Nothing is enforced, audited or held for review. Use it before publishing a change.

import { useState, type FormEvent } from "react";

import {
  Badge,
  Button,
  Card,
  DecisionBadge,
  EmptyState,
  ErrorBanner,
  Field,
  Json,
  KeyValue,
  ModeBadge,
  Mono,
  Notice,
  PageHeader,
} from "../components/ui";
import { ms } from "../lib/format";
import { useAction, useResource } from "../lib/hooks";
import { useSession } from "../lib/session";
import {
  ENVIRONMENTS,
  STAGES,
  type DataClassification,
  type Environment,
  type SimulationResult,
  type Stage,
} from "../lib/types";

const CLASSIFICATIONS: DataClassification[] = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII"];

/** Builds the stage's payload from the form. Retrieval takes one chunk per line; tool takes JSON arguments. */
export function buildPayload(stage: Stage, text: string, toolName: string, toolArgs: string): Record<string, unknown> {
  if (stage === "retrieval") {
    return {
      chunks: text
        .split("\n")
        .map((t) => t.trim())
        .filter(Boolean)
        .map((t, i) => ({ id: `c${i + 1}`, text: t })),
    };
  }
  if (stage === "tool") {
    let args: unknown = {};
    if (toolArgs.trim()) args = JSON.parse(toolArgs);
    if (!args || typeof args !== "object" || Array.isArray(args)) throw new Error("arguments must be a JSON object");
    return { tool_call: { name: toolName, arguments: args } };
  }
  return { text };
}

export function SimulatePage() {
  const { api, me } = useSession();
  const tenants = useResource(() => api.tenants(), [api]);
  const [env, setEnv] = useState<Environment>("dev");
  const [source, setSource] = useState<"working" | "current">("working");
  const [tenant, setTenant] = useState(me.tenant_id ?? "");
  const [stage, setStage] = useState<Stage>("input");
  const [agent, setAgent] = useState("research-agent");
  const [action, setAction] = useState("llm.chat");
  const [classification, setClassification] = useState<DataClassification>("PII");
  const [text, setText] = useState("Email jane.doe@example.com about invoice EMP-123456");
  const [toolName, setToolName] = useState("http.post");
  const [toolArgs, setToolArgs] = useState('{"url": "https://example.com", "body": "call me on 555-0100"}');
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const tenantId = tenant || tenants.data?.[0]?.id || "";
  const run = useAction(async () => {
    setFormError(null);
    let payload: Record<string, unknown>;
    try {
      payload = buildPayload(stage, text, toolName, toolArgs);
    } catch {
      setFormError("Tool arguments must be a JSON object.");
      return;
    }
    setResult(
      await api.simulate({
        environment: env,
        source,
        tenant_id: tenantId,
        stage,
        request: { agent_id: agent, action, data_classification: classification, payload },
      }),
    );
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run.run();
  };

  return (
    <>
      <PageHeader
        title="Simulate"
        description="Send a test request through a draft or the live pipeline on a real gateway. Nothing is enforced or audited."
      />
      <div className="split">
        <Card title="Request">
          <form onSubmit={submit}>
            <div className="form-row">
              <Field label="Environment" htmlFor="s-env">
                <select id="s-env" className="select" value={env} onChange={(e) => setEnv(e.target.value as Environment)}>
                  {ENVIRONMENTS.map((x) => (
                    <option key={x}>{x}</option>
                  ))}
                </select>
              </Field>
              <Field label="Pipeline" htmlFor="s-source">
                <select
                  id="s-source"
                  className="select"
                  value={source}
                  onChange={(e) => setSource(e.target.value as "working" | "current")}
                >
                  <option value="working">working set (draft)</option>
                  <option value="current">live snapshot</option>
                </select>
              </Field>
              <Field label="Tenant" htmlFor="s-tenant">
                <select id="s-tenant" className="select" value={tenantId} onChange={(e) => setTenant(e.target.value)}>
                  {(tenants.data ?? []).map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.id}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
            <div className="form-row">
              <Field label="Stage" htmlFor="s-stage">
                <select id="s-stage" className="select" value={stage} onChange={(e) => setStage(e.target.value as Stage)}>
                  {STAGES.map((x) => (
                    <option key={x}>{x}</option>
                  ))}
                </select>
              </Field>
              <Field label="Agent" htmlFor="s-agent">
                <input id="s-agent" className="input" value={agent} onChange={(e) => setAgent(e.target.value)} />
              </Field>
              <Field label="Action" htmlFor="s-action">
                <input id="s-action" className="input" value={action} onChange={(e) => setAction(e.target.value)} />
              </Field>
              <Field label="Data classification" htmlFor="s-class">
                <select
                  id="s-class"
                  className="select"
                  value={classification}
                  onChange={(e) => setClassification(e.target.value as DataClassification)}
                >
                  {CLASSIFICATIONS.map((c) => (
                    <option key={c}>{c}</option>
                  ))}
                </select>
              </Field>
            </div>
            {stage === "tool" ? (
              <>
                <Field label="Tool name" htmlFor="s-tool">
                  <input id="s-tool" className="input" value={toolName} onChange={(e) => setToolName(e.target.value)} />
                </Field>
                <Field label="Tool arguments (JSON)" htmlFor="s-args">
                  <textarea id="s-args" className="textarea" rows={5} value={toolArgs} onChange={(e) => setToolArgs(e.target.value)} />
                </Field>
              </>
            ) : (
              <Field
                label={stage === "retrieval" ? "Retrieved chunks (one per line)" : "Text"}
                htmlFor="s-text"
              >
                <textarea id="s-text" className="textarea" rows={6} value={text} onChange={(e) => setText(e.target.value)} />
              </Field>
            )}
            {formError && <Notice tone="warning">{formError}</Notice>}
            <ErrorBanner error={run.error} title="Simulation failed" />
            <Button type="submit" variant="primary" busy={run.busy} disabled={!tenantId || !agent || !action}>
              Run simulation
            </Button>
          </form>
        </Card>
        <SimulationOutput result={result} />
      </div>
    </>
  );
}

function SimulationOutput({ result }: { result: SimulationResult | null }) {
  if (!result) {
    return (
      <Card title="Result">
        <EmptyState title="No simulation yet">Each guardrail's decision, the policy result and the final payload appear here.</EmptyState>
      </Card>
    );
  }
  const r = result.result;
  return (
    <Card
      title={
        <span className="row">
          Result <DecisionBadge decision={r.decision} />
        </span>
      }
    >
      <div className="stack">
        {result.warnings.map((w, i) => (
          <Notice key={i} tone="warning">
            {w}
          </Notice>
        ))}
        <KeyValue
          items={[
            ["Decision", <DecisionBadge key="d" decision={r.decision} />],
            ["Reason", r.reason],
            ["Snapshot", <Mono key="s">{result.snapshot}</Mono>],
            ["Environment", r.simulated_on !== r.environment ? `${r.environment} (run on a ${r.simulated_on} gateway)` : r.environment],
            ["Trust / risk", `${r.trust_score} / ${r.risk_score}`],
            [
              "Policy (OPA)",
              r.policy.allow ? (
                <Badge key="p" tone="good">allowed</Badge>
              ) : (
                <span key="p">
                  <Badge tone="critical">denied</Badge> {r.policy.reason}
                </span>
              ),
            ],
            ["Obligations", r.policy.obligations.length ? r.policy.obligations.join(", ") : "none"],
          ]}
        />
        <div className="table-wrap">
          <table className="table table-compact">
            <thead>
              <tr>
                <th scope="col">Guardrail</th>
                <th scope="col">Mode</th>
                <th scope="col">Decision</th>
                <th scope="col" className="num">
                  Latency
                </th>
              </tr>
            </thead>
            <tbody>
              {r.results.length === 0 ? (
                <tr>
                  <td colSpan={4} className="muted">
                    No guardrail ran{r.policy.allow ? " (nothing assigned to this stage)" : " (policy denied first)"}.
                  </td>
                </tr>
              ) : (
                r.results.map((g) => (
                  <tr key={`${g.guardrail_id}@${g.version}`}>
                    <td>
                      {g.guardrail_id}@{g.version}
                      <span className="cell-sub">
                        {g.error ? `error: ${g.error}` : g.reason}
                        {g.findings.length > 0 &&
                          ` · ${g.findings.map((f) => f.entity_type ?? "finding").join(", ")}`}
                      </span>
                    </td>
                    <td>
                      <ModeBadge mode={g.mode === "enforce" ? "enforce" : "shadow"} />
                    </td>
                    <td>
                      <DecisionBadge decision={g.decision} />
                    </td>
                    <td className="num">{ms(g.latency_ms)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <div>
          <p className="field-label">Payload the agent would get</p>
          {r.payload ? <Json value={r.payload} maxHeight="sm" /> : <p className="muted">Nothing: the request is blocked or held.</p>}
        </div>
      </div>
    </Card>
  );
}
