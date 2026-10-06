// The decision log: the gateway's audit records, one per request, newest first. Shows why each
// decision was made (reason codes, risk signals, policy, guardrails, advisors) and the record's
// place in its hash chain. Payload text is never stored, only its SHA-256.

import { useState } from "react";

import {
  AdvisorAnswers,
  findingTypes,
  GuardrailTable,
  OutcomeBadge,
  ReasonCodes,
  RiskSummary,
} from "../components/DecisionDetail";
import {
  Badge,
  Card,
  DecisionBadge,
  Dialog,
  EmptyState,
  ErrorBanner,
  Json,
  KeyValue,
  Loading,
  Mono,
  PageHeader,
  Toolbar,
} from "../components/ui";
import { ApiError } from "../lib/api";
import { dateTime, ms } from "../lib/format";
import { useResource } from "../lib/hooks";
import { useQueryParam, useRoute } from "../lib/router";
import { useSession } from "../lib/session";
import { ENVIRONMENTS, type DecisionRecord, type Environment, type Stage } from "../lib/types";

const DECISIONS = ["", "allow", "modify", "escalate", "block"];
const STAGES: (Stage | "")[] = ["", "input", "retrieval", "tool", "output"];
const HOURS = [1, 24, 24 * 7, 24 * 30];

export function DecisionsPage() {
  const { api, me } = useSession();
  const route = useRoute();
  const tenants = useResource(() => (me.platform ? api.tenants() : Promise.resolve([])), [api]);
  const [requestId, setRequestId] = useQueryParam(route, "request");
  const [env, setEnv] = useQueryParam(route, "environment");
  const [tenant, setTenant] = useQueryParam(route, "tenant");
  const [agent, setAgent] = useQueryParam(route, "agent");
  const [decision, setDecision] = useQueryParam(route, "decision");
  const [stage, setStage] = useQueryParam(route, "stage");
  const [hours, setHours] = useState(24);
  const [agentDraft, setAgentDraft] = useState(agent);

  const log = useResource(
    () =>
      api.decisions({
        environment: (env || "") as Environment | "",
        tenant_id: tenant || undefined,
        hours,
        limit: 100,
        agent_id: agent || undefined,
        decision: decision || undefined,
        stage: (stage || "") as Stage | "",
      }),
    [api, env, tenant, agent, decision, stage, hours],
    15_000,
  );
  // The gateway writes audit records about once a second, so a just-sent request may need a moment.
  const open = useResource(
    () => (requestId ? withRetry(() => api.decision(requestId)) : Promise.resolve(null)),
    [api, requestId],
  );

  return (
    <>
      <PageHeader
        title="Decision log"
        description="Every decision the gateways made, from the audit log: why it was made and its place in the tamper-evident hash chain. Payloads are never stored."
      />
      <Toolbar>
        <select className="select select-auto" aria-label="Environment" value={env} onChange={(e) => setEnv(e.target.value || null)}>
          <option value="">All environments</option>
          {ENVIRONMENTS.map((x) => (
            <option key={x}>{x}</option>
          ))}
        </select>
        {me.platform && (tenants.data?.length ?? 0) > 1 && (
          <select className="select select-auto" aria-label="Tenant" value={tenant} onChange={(e) => setTenant(e.target.value || null)}>
            <option value="">All tenants</option>
            {(tenants.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.id}
              </option>
            ))}
          </select>
        )}
        <select className="select select-auto" aria-label="Decision" value={decision} onChange={(e) => setDecision(e.target.value || null)}>
          {DECISIONS.map((d) => (
            <option key={d} value={d}>
              {d || "Any decision"}
            </option>
          ))}
        </select>
        <select className="select select-auto" aria-label="Stage" value={stage} onChange={(e) => setStage(e.target.value || null)}>
          {STAGES.map((s) => (
            <option key={s} value={s}>
              {s || "Any stage"}
            </option>
          ))}
        </select>
        <select className="select select-auto" aria-label="Window" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
          {HOURS.map((h) => (
            <option key={h} value={h}>
              {h < 24 ? `Last ${h} hour` : h === 24 ? "Last 24 hours" : `Last ${h / 24} days`}
            </option>
          ))}
        </select>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setAgent(agentDraft.trim() || null);
          }}
        >
          <input
            className="input"
            aria-label="Agent id"
            placeholder="Agent id"
            value={agentDraft}
            onChange={(e) => setAgentDraft(e.target.value)}
          />
        </form>
      </Toolbar>
      <ErrorBanner error={log.error} />
      <Card flush>
        {log.data === undefined ? (
          <Loading />
        ) : log.data.decisions.length === 0 ? (
          <EmptyState title="No decisions in this window">Send a request (Playground, or an agent) and it appears here within a second or two.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Agent / action</th>
                  <th scope="col">Stage</th>
                  <th scope="col">Decision</th>
                  <th scope="col">Outcome</th>
                  <th scope="col" className="num">
                    Risk
                  </th>
                  <th scope="col">Why</th>
                </tr>
              </thead>
              <tbody>
                {log.data.decisions.map((d) => (
                  <tr key={d.request_id} className="col-hover">
                    <td className="nowrap">
                      <button type="button" className="link-btn" onClick={() => setRequestId(d.request_id)}>
                        {dateTime(d.created_at)}
                      </button>
                    </td>
                    <td>
                      {d.agent_id}
                      <span className="cell-sub">
                        {d.action} · {d.tenant_id}/{d.environment}
                      </span>
                    </td>
                    <td>{d.stage}</td>
                    <td>
                      <DecisionBadge decision={d.decision} />
                    </td>
                    <td>
                      <OutcomeBadge outcome={d.outcome} />
                    </td>
                    <td className="num">{d.risk?.score ?? d.risk_score}</td>
                    <td>
                      <span className="cell-sub">{why(d)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {requestId && (
        <Dialog title="Decision" open onClose={() => setRequestId(null)} wide>
          {open.data === undefined && !open.error ? (
            <Loading />
          ) : open.error ? (
            <ErrorBanner error={open.error} title="No audit record yet" />
          ) : open.data ? (
            <DecisionView d={open.data} />
          ) : null}
        </Dialog>
      )}
    </>
  );
}

async function withRetry<T>(load: () => Promise<T>, tries = 6, delayMs = 700): Promise<T> {
  for (let i = 1; ; i++) {
    try {
      return await load();
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 404 || i >= tries) throw e;
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

/** One line: the most telling reason codes, else the reason. */
function why(d: DecisionRecord): string {
  const shown = d.reason_codes.filter((c) => !["NO_SESSION", "NEW_SESSION", "LOW_CONFIDENCE"].includes(c)).slice(0, 4);
  const blocking = d.guardrail_results.filter((g) => g.decision !== "allow");
  const parts = [...shown];
  for (const g of blocking) parts.push(`${g.guardrail_id}${g.mode === "shadow" ? " (shadow)" : ""}: ${g.decision}${g.findings.length ? ` ${findingTypes(g)}` : ""}`);
  if (!d.policy_allow) parts.push(`policy: ${d.policy_reason}`);
  return parts.length ? parts.join(" · ") : d.reason;
}

function DecisionView({ d }: { d: DecisionRecord }) {
  return (
    <div className="stack">
      <div className="row">
        <DecisionBadge decision={d.decision} />
        <OutcomeBadge outcome={d.outcome} />
        <span className="muted">
          {d.stage} · {d.agent_id} · {d.action}
          {d.resource ? ` on ${d.resource}` : ""}
        </span>
      </div>
      <KeyValue
        items={[
          ["When", dateTime(d.created_at)],
          ["Request", <Mono key="r">{d.request_id}</Mono>],
          ["Tenant / environment", `${d.tenant_id} / ${d.environment}`],
          ["Session / user", `${d.session_id ?? "none"} / ${d.user_id ?? "none"}`],
          ["Reason", d.reason],
          ["Reason codes", <ReasonCodes key="c" codes={d.reason_codes} />],
          [
            "Policy (OPA)",
            d.policy_allow ? (
              <Badge key="p" tone="good">allowed</Badge>
            ) : (
              <span key="p">
                <Badge tone="critical">denied</Badge> {d.policy_reason}
              </span>
            ),
          ],
          ["Identity assurance", d.assurance ?? "?"],
          ["Snapshot", <Mono key="s">{d.snapshot_version ?? "?"}</Mono>],
          ["Latency", ms(d.latency_ms ?? 0)],
        ]}
      />
      <section>
        <h3 className="card-title">Risk</h3>
        <RiskSummary risk={d.risk} />
      </section>
      <section>
        <h3 className="card-title">Guardrails</h3>
        <GuardrailTable
          results={d.guardrail_results}
          emptyText={d.policy_allow ? "No guardrail is assigned to this stage." : "No guardrail ran: the policy denied the request first."}
        />
      </section>
      <section>
        <h3 className="card-title">Advisors</h3>
        <AdvisorAnswers risk={d.risk} />
      </section>
      {d.descriptor && (
        <section>
          <h3 className="card-title">Action descriptor</h3>
          <p className="field-hint">What the gateway understood the action to do: names, hosts and counts, never values.</p>
          <Json value={d.descriptor} maxHeight="sm" />
        </section>
      )}
      <section>
        <h3 className="card-title">Audit record</h3>
        <KeyValue
          items={[
            ["Payload SHA-256", <Mono key="h">{d.payload_sha256}</Mono>],
            ["Hash chain", d.chain_id ? `${d.chain_id} #${d.chain_seq}` : "not chained"],
            ["Previous hash", <Mono key="p">{d.prev_hash ?? "-"}</Mono>],
            ["Record hash", <Mono key="r">{d.record_hash ?? "-"}</Mono>],
          ]}
        />
      </section>
    </div>
  );
}
