// How one decision is shown, whether it comes straight from the gateway (Playground) or from the
// audit log (Decision log): the outcome, why (reason codes, risk signals, policy, each
// guardrail), and for audit records the advisor answers and the hash-chain fields.

import type { ReactNode } from "react";

import { ms } from "../lib/format";
import type { AdvisorAnswer, GuardrailOutcome, RiskInfo } from "../lib/types";
import { Badge, DecisionBadge, KeyValue, ModeBadge, Mono, type Tone } from "./ui";

const BAND_TONE: Record<string, Tone> = { low: "neutral", elevated: "warning", high: "serious", critical: "critical" };

/** The decision table's outcome (allow, allow_restricted, modify, verify, hold, deny, quarantine_session). */
export function outcomeTone(outcome: string | null | undefined): Tone {
  switch (outcome) {
    case "allow":
    case "allow_restricted":
      return "good";
    case "modify":
      return "info";
    case "verify":
    case "hold":
      return "warning";
    case "deny":
    case "quarantine_session":
      return "critical";
    default:
      return "neutral";
  }
}

export function OutcomeBadge({ outcome }: { outcome: string | null | undefined }) {
  if (!outcome) return <span className="muted">none</span>;
  return <Badge tone={outcomeTone(outcome)}>{outcome.replace(/_/g, " ")}</Badge>;
}

export function BandBadge({ band }: { band: string }) {
  return (
    <Badge tone={BAND_TONE[band] ?? "neutral"} icon={false}>
      {band}
    </Badge>
  );
}

export function ReasonCodes({ codes }: { codes: string[] }) {
  if (codes.length === 0) return <span className="muted">none</span>;
  return (
    <span className="row">
      {codes.map((c) => (
        <span key={c} className="tag">
          {c}
        </span>
      ))}
    </span>
  );
}

export function RiskSummary({ risk }: { risk: RiskInfo | null | undefined }) {
  if (!risk) return <p className="muted">No contextual risk (RISK_MODE=off, or the request was refused before scoring).</p>;
  return (
    <div className="stack-tight">
      <KeyValue
        items={[
          [
            "Risk",
            <span key="r" className="row">
              <strong>{risk.score}</strong> <BandBadge band={risk.band} /> <ModeBadge mode={risk.mode === "enforce" ? "enforce" : "shadow"} />
            </span>,
          ],
          ["Decision table", <OutcomeBadge key="w" outcome={risk.would_outcome} />],
          ["Trust (now)", String(risk.trust)],
          ["Confidence", `${Math.round(risk.confidence * 100)}%`],
        ]}
      />
      {risk.mode !== "enforce" && (
        <p className="field-hint">
          Shadow mode: the decision table's outcome is recorded, not enforced (RISK_MODE=enforce enforces it).
        </p>
      )}
      {risk.signals.length > 0 && (
        <div className="table-wrap">
          <table className="table table-compact">
            <thead>
              <tr>
                <th scope="col">Signal</th>
                <th scope="col" className="num">
                  Points
                </th>
                <th scope="col">Detail</th>
              </tr>
            </thead>
            <tbody>
              {risk.signals.map((s, i) => (
                <tr key={`${s.code}-${i}`}>
                  <td>
                    <Mono>{s.code}</Mono>
                  </td>
                  <td className="num">+{s.points}</td>
                  <td className="muted">{s.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function GuardrailTable({ results, emptyText }: { results: GuardrailOutcome[]; emptyText: ReactNode }) {
  return (
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
          {results.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                {emptyText}
              </td>
            </tr>
          ) : (
            results.map((g) => (
              <tr key={`${g.guardrail_id}@${g.version}`}>
                <td>
                  {g.guardrail_id}@{g.version}
                  <span className="cell-sub">
                    {g.error ? `error: ${g.error}` : g.reason}
                    {g.findings.length > 0 && ` · ${findingTypes(g)}`}
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
  );
}

/** Finding types only: findings never carry the matched text. */
export function findingTypes(g: GuardrailOutcome): string {
  const types = g.findings.map((f) => f.entity_type ?? f.type ?? "finding");
  return Array.from(new Set(types)).join(", ");
}

export function AdvisorAnswers({ risk }: { risk: RiskInfo | null | undefined }) {
  const adv = risk?.advisors;
  if (!adv) {
    return <p className="muted">No advisor ran (they only run in the elevated and high risk bands).</p>;
  }
  return (
    <div className="stack-tight">
      <KeyValue
        items={[
          ["Points added (enforced)", String(adv.points)],
          ["Would add (shadow)", String(adv.shadow_points)],
          ["Asked to verify", adv.verify ? "yes" : adv.shadow_verify ? "shadow only" : "no"],
        ]}
      />
      <div className="table-wrap">
        <table className="table table-compact">
          <thead>
            <tr>
              <th scope="col">Advisor</th>
              <th scope="col">Question</th>
              <th scope="col">Answer</th>
              <th scope="col" className="num">
                Points
              </th>
            </tr>
          </thead>
          <tbody>
            {adv.answers.map((a: AdvisorAnswer, i) => (
              <tr key={`${a.advisor}-${a.question}-${i}`}>
                <td>
                  {a.advisor} <ModeBadge mode={a.mode === "enforce" ? "enforce" : "shadow"} />
                </td>
                <td>{a.question}</td>
                <td>
                  {a.status === "answered" ? (
                    <>
                      {a.label} <span className="muted">({Math.round((a.confidence ?? 0) * 100)}%)</span>
                    </>
                  ) : (
                    <span className="muted">{a.status.replace(/_/g, " ")}</span>
                  )}
                </td>
                <td className="num">{a.points ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
