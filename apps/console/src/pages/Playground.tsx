// Send a real agent request through the gateway with an agent's key. Unlike Simulate, this is the
// enforcement path: session risk, the decision table, the review queue and the audit log all apply.

import { useMemo, useState, type FormEvent } from "react";

import {
  GuardrailTable,
  OutcomeBadge,
  ReasonCodes,
  RiskSummary,
} from "../components/DecisionDetail";
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
  Mono,
  Notice,
  PageHeader,
} from "../components/ui";
import { useAction } from "../lib/hooks";
import { buildGuardRequest, newSessionId, SCENARIOS, type PlaygroundForm, type Scenario } from "../lib/playground";
import { navigate } from "../lib/router";
import { useSession } from "../lib/session";
import type { DataClassification, Environment, PlaygroundResult, Stage } from "../lib/types";

const CLASSIFICATIONS: DataClassification[] = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII"];
const PLAYGROUND_STAGES: Stage[] = ["input", "retrieval", "tool", "output"];

const INITIAL: PlaygroundForm = {
  stage: "input",
  agent: "research-agent",
  action: "llm.chat",
  resource: "",
  userId: "u1",
  sessionId: newSessionId(),
  classification: "INTERNAL",
  text: "Summarise our refund policy in three bullet points.",
  toolName: "http.post",
  toolArgs: '{"url": "https://partner.example.net/hook", "body": "hello"}',
  toolResult: "",
};

export function PlaygroundPage() {
  const { api, me } = useSession();
  const environments = me.features.playground ?? [];
  const [env, setEnv] = useState<Environment>(environments[0] ?? "dev");
  // The key lives in this component's state only: never stored, never sent anywhere but /playground.
  const [gatewayKey, setGatewayKey] = useState("");
  const [form, setForm] = useState<PlaygroundForm>(INITIAL);
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [history, setHistory] = useState<PlaygroundResult[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const set = <K extends keyof PlaygroundForm>(k: K, v: PlaygroundForm[K]) => setForm((f) => ({ ...f, [k]: v }));

  const preview = useMemo(() => {
    try {
      return buildGuardRequest(form);
    } catch {
      return null;
    }
  }, [form]);

  const apply = (s: Scenario) => {
    setScenario(s);
    setFormError(null);
    setForm((f) => ({
      ...f,
      resource: "",
      toolResult: "",
      ...s.form(),
      sessionId: s.session === "same" ? f.sessionId : newSessionId(),
    }));
  };

  const send = useAction(async () => {
    setFormError(null);
    let request;
    try {
      request = buildGuardRequest(form);
    } catch {
      setFormError("Tool arguments must be a JSON object.");
      return;
    }
    const out = await api.playground({ environment: env, stage: form.stage, gateway_key: gatewayKey.trim(), request });
    setHistory((h) => [out, ...h].slice(0, 10));
  });

  const poll = useAction(async (id: string) => {
    const out = await api.playgroundEscalation(id, { environment: env, gateway_key: gatewayKey.trim() });
    setHistory((h) => [out, ...h].slice(0, 10));
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void send.run();
  };

  if (environments.length === 0) {
    return (
      <>
        <PageHeader title="Playground" />
        <EmptyState title="The playground is off">
          Set <Mono>PLAYGROUND_ENVIRONMENTS</Mono> on the control plane (for example <Mono>["dev"]</Mono>) to send real
          agent requests from the console.
        </EmptyState>
      </>
    );
  }

  const groups = Array.from(new Set(SCENARIOS.map((s) => s.group)));
  return (
    <>
      <PageHeader
        title="Playground"
        description="Act as an agent: send a real request through the gateway with an agent's key. It is scored, enforced, held for review if needed and audited, like any agent request."
      />
      <Card title="Scenarios">
        <div className="stack-tight">
          {groups.map((g) => (
            <div key={g} className="row">
              <span className="field-label">{g}</span>
              {SCENARIOS.filter((s) => s.group === g).map((s) => (
                <Button key={s.id} size="sm" variant={scenario?.id === s.id ? "primary" : "secondary"} onClick={() => apply(s)}>
                  {s.label}
                </Button>
              ))}
            </div>
          ))}
          {scenario && (
            <Notice tone="info">
              <strong>{scenario.label}.</strong> Expected with the default dev setup: {scenario.expect}.
            </Notice>
          )}
        </div>
      </Card>
      <div className="split section-gap">
        <Card title="Request">
          <form onSubmit={submit}>
            <div className="form-row">
              <Field label="Environment" htmlFor="p-env">
                <select id="p-env" className="select" value={env} onChange={(e) => setEnv(e.target.value as Environment)}>
                  {environments.map((x) => (
                    <option key={x}>{x}</option>
                  ))}
                </select>
              </Field>
              <Field label="Agent's gateway key" htmlFor="p-key" hint="A gk_ key from Tenants & keys. Kept in this page only.">
                <input
                  id="p-key"
                  className="input"
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="gk_..."
                  value={gatewayKey}
                  onChange={(e) => setGatewayKey(e.target.value)}
                />
              </Field>
            </div>
            <div className="form-row">
              <Field label="Stage" htmlFor="p-stage">
                <select id="p-stage" className="select" value={form.stage} onChange={(e) => set("stage", e.target.value as Stage)}>
                  {PLAYGROUND_STAGES.map((x) => (
                    <option key={x}>{x}</option>
                  ))}
                </select>
              </Field>
              <Field label="Agent" htmlFor="p-agent">
                <input id="p-agent" className="input" value={form.agent} onChange={(e) => set("agent", e.target.value)} />
              </Field>
              <Field label="Action" htmlFor="p-action">
                <input id="p-action" className="input" value={form.action} onChange={(e) => set("action", e.target.value)} />
              </Field>
              <Field label="Data classification" htmlFor="p-class">
                <select
                  id="p-class"
                  className="select"
                  value={form.classification}
                  onChange={(e) => set("classification", e.target.value as DataClassification)}
                >
                  {CLASSIFICATIONS.map((c) => (
                    <option key={c}>{c}</option>
                  ))}
                </select>
              </Field>
            </div>
            <div className="form-row">
              <Field
                label="Session"
                htmlFor="p-session"
                hint={
                  <>
                    Risk builds up per session; scenarios start a new one.{" "}
                    <button type="button" className="link-btn" onClick={() => set("sessionId", newSessionId())}>
                      New session
                    </button>
                  </>
                }
              >
                <input id="p-session" className="input" value={form.sessionId} onChange={(e) => set("sessionId", e.target.value)} />
              </Field>
              <Field label="User" htmlFor="p-user">
                <input id="p-user" className="input" value={form.userId} onChange={(e) => set("userId", e.target.value)} />
              </Field>
              <Field label="Resource (optional)" htmlFor="p-resource">
                <input id="p-resource" className="input" value={form.resource} onChange={(e) => set("resource", e.target.value)} />
              </Field>
            </div>
            {form.stage === "tool" ? (
              <>
                <Field label="Tool name" htmlFor="p-tool">
                  <input id="p-tool" className="input" value={form.toolName} onChange={(e) => set("toolName", e.target.value)} />
                </Field>
                <Field label="Tool arguments (JSON)" htmlFor="p-args">
                  <textarea id="p-args" className="textarea" rows={4} value={form.toolArgs} onChange={(e) => set("toolArgs", e.target.value)} />
                </Field>
                <Field label="Tool result (optional, JSON or text)" htmlFor="p-result" hint="Guarded as untrusted content, like a real tool's output.">
                  <textarea id="p-result" className="textarea" rows={3} value={form.toolResult} onChange={(e) => set("toolResult", e.target.value)} />
                </Field>
              </>
            ) : (
              <Field label={form.stage === "retrieval" ? "Retrieved chunks (one per line)" : "Text"} htmlFor="p-text">
                <textarea id="p-text" className="textarea" rows={5} value={form.text} onChange={(e) => set("text", e.target.value)} />
              </Field>
            )}
            {formError && <Notice tone="warning">{formError}</Notice>}
            <ErrorBanner error={send.error ?? poll.error} title="Request failed" />
            <Button type="submit" variant="primary" busy={send.busy} disabled={!gatewayKey.trim() || !preview}>
              Send as agent
            </Button>
            <details className="section-gap">
              <summary className="field-label">Request body the agent sends</summary>
              {preview ? <Json value={preview} maxHeight="sm" /> : <p className="muted">Fix the tool arguments first.</p>}
            </details>
          </form>
        </Card>
        <Card title="Responses">
          {history.length === 0 ? (
            <EmptyState title="Nothing sent yet">The gateway's answer appears here, newest first, with a link to its audit record.</EmptyState>
          ) : (
            <div className="stack">
              {history.map((r, i) => (
                <PlaygroundAnswer key={`${r.response.request_id ?? r.response.escalation_id ?? "x"}-${history.length - i}`} result={r} onPoll={(id) => void poll.run(id)} polling={poll.busy} />
              ))}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}

function statusTone(status: number) {
  if (status === 200) return "good" as const;
  if (status === 202) return "warning" as const;
  return "critical" as const;
}

function PlaygroundAnswer({
  result,
  onPoll,
  polling,
}: {
  result: PlaygroundResult;
  onPoll: (escalationId: string) => void;
  polling: boolean;
}) {
  const r = result.response;
  // An escalation poll answers {escalation_id, decision, payload}; a guard call answers a GuardResponse.
  const isPoll = r.request_id === undefined && r.escalation_id !== undefined;
  if (r.error !== undefined || r.decision === undefined) {
    return (
      <Notice tone="warning">
        <strong>HTTP {result.status}</strong> {r.error ?? JSON.stringify(r.detail ?? r)}
        {result.retry_after && ` (retry after ${result.retry_after}s)`}
      </Notice>
    );
  }
  if (isPoll) {
    return (
      <div className="card stack-tight">
        <KeyValue
          items={[
            ["Held request", <Mono key="e">{r.escalation_id}</Mono>],
            ["Review", r.status ?? "?"],
            ["Agent gets", <DecisionBadge key="d" decision={r.decision} />],
            ["Reviewer", r.reviewer ?? "nobody yet"],
          ]}
        />
        {r.payload ? <Json value={r.payload} maxHeight="sm" /> : null}
        <p className="field-hint">escalate = still waiting for a reviewer; allow = approved, the held payload is released; block = rejected or expired.</p>
      </div>
    );
  }
  return (
    <div className="card stack-tight">
      <div className="row">
        <Badge tone={statusTone(result.status)} icon={false}>
          HTTP {result.status}
        </Badge>
        <DecisionBadge decision={r.decision} />
        <OutcomeBadge outcome={r.outcome} />
        <span className="muted">
          {r.stage} · {result.key.name} ({result.key.prefix}…)
        </span>
      </div>
      <KeyValue
        items={[
          ["Reason", r.reason ?? ""],
          ["Reason codes", <ReasonCodes key="c" codes={r.reason_codes ?? []} />],
          [
            "Policy (OPA)",
            r.policy?.allow ? (
              <Badge key="p" tone="good">allowed</Badge>
            ) : (
              <span key="p">
                <Badge tone="critical">denied</Badge> {r.policy?.reason}
              </span>
            ),
          ],
          ["Identity assurance", r.assurance ?? "?"],
          ["Snapshot", <Mono key="s">{r.snapshot_version ?? "?"}</Mono>],
        ]}
      />
      {r.escalation_id && (
        <Notice tone="warning">
          Held for a person: it is in the Review queue now. The agent polls it until a reviewer decides.{" "}
          <span className="row">
            <Button size="sm" busy={polling} onClick={() => onPoll(r.escalation_id as string)}>
              Check as the agent
            </Button>
            <Button size="sm" variant="ghost" onClick={() => navigate("/reviews")}>
              Open review queue
            </Button>
          </span>
        </Notice>
      )}
      {r.verification && (
        <Notice tone="warning">
          User confirmation needed ({r.verification.summary}). The user confirms through the gateway's verification API,
          then the agent retries the same request.
        </Notice>
      )}
      <RiskSummary risk={r.risk} />
      <GuardrailTable
        results={r.results ?? []}
        emptyText={r.policy?.allow === false ? "No guardrail ran: the policy denied the request first." : "No guardrail is assigned to this stage."}
      />
      <div>
        <p className="field-label">Payload the agent gets</p>
        {r.payload ? <Json value={r.payload} maxHeight="sm" /> : <p className="muted">Nothing: the request is blocked or held.</p>}
      </div>
      {r.request_id && (
        <Button size="sm" variant="ghost" onClick={() => navigate("/decisions", { request: r.request_id })}>
          Open audit record
        </Button>
      )}
      {r.risk && <p className="field-hint">Advisor answers are never returned to the agent; the audit record shows them.</p>}
    </div>
  );
}
