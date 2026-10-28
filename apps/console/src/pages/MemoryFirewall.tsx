// Memory Firewall (services/memory-firewall): agents may only use memory whose writer is authorized
// and whose source is trusted. This page shows the service's health and signing key, checks memory
// items against it, runs the checkpoint self-test, and reads its event log. Everything is relayed
// by the control plane (/cp/v1/memory-firewall); the console never talks to the service directly.

import { useEffect, useState, type FormEvent, type ReactNode } from "react";

import { IconPlus, IconRefresh, IconTrash } from "../components/icons";
import { useToast } from "../components/toast";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  Field,
  KeyValue,
  Loading,
  Mono,
  Notice,
  PageHeader,
} from "../components/ui";
import { dateTime, ms, percent, relativeTime } from "../lib/format";
import { useAction, useNow, useResource } from "../lib/hooks";
import {
  blankItem,
  eventTone,
  MEMORY_SOURCES,
  MODE_LABEL,
  OUTCOME_VIEW,
  SAMPLE_ITEMS,
  scanLabel,
  selfTestMatrix,
  serviceHealth,
  trimItems,
  uptime,
  validateItems,
  verdictView,
} from "../lib/memoryFirewall";
import { useSession } from "../lib/session";
import type { InspectResult, MemoryFirewallStatus, MemoryItem, SelfTestResult } from "../lib/types";

export function MemoryFirewallPage() {
  const { api, me, can } = useSession();
  const now = useNow(30_000);
  const canRun = me.platform && can("catalog:write");
  const canSeeEvents = me.platform && can("read");
  // Bumped by Refresh and after every check or self-test, so the counters and event log follow.
  // (reload() keeps the last data on screen; changing useResource's deps would blank it.)
  const [revision, setRevision] = useState(0);
  const status = useResource(() => api.memoryFirewallStatus(), [api], 15_000);
  const refresh = () => {
    void status.reload();
    setRevision((r) => r + 1);
  };
  const registry = useResource(
    () => api.guardrails().then((all) => all.filter((g) => g.guardrail_id === "memory-firewall")),
    [api],
  );
  const s = status.data;
  const svc = s?.service;
  const health = serviceHealth(s);
  const online = Boolean(s?.reachable && svc);

  return (
    <>
      <PageHeader
        title="Memory Firewall"
        description="Agents may only use memory whose writer is authorized and whose source is trusted; the rest is quarantined. Stored checkpoints are signed and verified before they are loaded."
        actions={
          <Button icon={<IconRefresh size={14} />} onClick={refresh} busy={status.loading && s !== undefined}>
            Refresh
          </Button>
        }
      />
      <ErrorBanner error={status.error} />
      {s === undefined ? (
        status.error ? null : <Loading label="Checking the Memory Firewall service" />
      ) : (
        <>
          <ServiceNotice status={s} />
          <div className="grid-stats">
            <div className="stat">
              <span className="stat-label">Service</span>
              <span className="stat-value">
                <Badge tone={health.tone}>{health.label}</Badge>
              </span>
              <span className="stat-hint">{s.latency_ms !== undefined ? `answered in ${ms(s.latency_ms)}` : "—"}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Memory admitted</span>
              <span className="stat-value">{svc ? svc.counters.admitted : "—"}</span>
              <span className="stat-hint">{svc ? `${svc.counters.provenance_records} signed provenance records` : "since the service started"}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Memory quarantined</span>
              <span className="stat-value">{svc ? svc.counters.quarantined : "—"}</span>
              <span className="stat-hint">{svc ? `${svc.counters.scan_flagged} flagged by the scan` : "since the service started"}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Checkpoint self-test</span>
              <span className="stat-value">
                {svc?.last_selftest ? `${svc.last_selftest.guard_blocked}/${svc.last_selftest.attacks}` : "—"}
              </span>
              <span className="stat-hint">
                {svc?.last_selftest ? (
                  <>
                    <Badge tone={svc.last_selftest.passed ? "good" : "critical"}>{svc.last_selftest.passed ? "all blocked" : "failed"}</Badge>
                    {relativeTime(svc.last_selftest.finished_at, now)}
                  </>
                ) : (
                  "not run since the service started"
                )}
              </span>
            </div>
          </div>

          <div className="split">
            <Card title="Service">
              <KeyValue
                items={[
                  ["Health", <Badge key="h" tone={health.tone}>{health.label}</Badge>],
                  ...(s.url ? ([["Endpoint", <Mono key="u">{s.url}</Mono>]] as [string, ReactNode][]) : []),
                  ["Versions", svc ? `service ${svc.version} · library ${svc.library_version}` : "—"],
                  ["Signing key", svc ? <Mono key="k">{svc.key_id}</Mono> : "—"],
                  [
                    "Trusted sources",
                    svc ? (
                      <span key="t">
                        {svc.sources.map((src) => (
                          <span key={src} className="tag">
                            {src}
                            {svc.trusted_sources.includes(src) ? " · trusted" : ""}
                          </span>
                        ))}
                      </span>
                    ) : (
                      "—"
                    ),
                  ],
                  ["Threat tag", svc ? <Mono key="m">{svc.mitre_technique}</Mono> : "—"],
                  ["Scan heuristics", svc ? `${svc.injection_patterns} instruction-injection patterns` : "—"],
                  ["Provenance coverage", svc ? percent(svc.counters.provenance_coverage) : "—"],
                  ["Up for", svc ? uptime(svc.uptime_seconds) : "—"],
                ]}
              />
            </Card>
            <Card title="In the pipeline">
              <p className="muted">
                The <Mono>memory-firewall</Mono> guardrail sends every retrieved memory chunk to this service at the
                retrieval stage. A chunk's source comes from its <Mono>metadata.source_type</Mono> and its writer from{" "}
                <Mono>metadata.writer</Mono>; quarantined or instruction-like chunks are dropped by default.
              </p>
              <div className="section-gap">
                {registry.data === undefined ? (
                  registry.error ? <ErrorBanner error={registry.error} /> : <Loading />
                ) : registry.data.length === 0 ? (
                  <Notice tone="warning">
                    The guardrail is not in the registry yet. Restart the control plane with the gateway plugins, or
                    register <Mono>memory_firewall/guardrail.yaml</Mono> on the Guardrails page.
                  </Notice>
                ) : (
                  <KeyValue
                    items={registry.data.map((g) => [
                      `${g.guardrail_id}@${g.version}`,
                      <span key={g.version} className="row">
                        <Badge tone={g.status === "validated" ? "good" : "neutral"}>{g.status}</Badge>
                        <span className="muted">
                          {g.manifest.stages.join(", ")} · {g.manifest.failure_mode}
                        </span>
                      </span>,
                    ])}
                  />
                )}
              </div>
              <p className="section-gap">
                <a href="#/pipeline">Assign it in the pipeline</a> (start in shadow) · <a href="#/guardrails">Guardrail registry</a>
              </p>
            </Card>
          </div>

          {canRun && <InspectCard disabled={!online} onDone={refresh} />}
          {canRun && <SelfTestCard disabled={!online} onDone={refresh} />}
          {canSeeEvents && online && <EventLogCard revision={revision} />}
        </>
      )}
    </>
  );
}

function ServiceNotice({ status }: { status: MemoryFirewallStatus }) {
  if (!status.configured)
    return (
      <Notice tone="info">
        The control plane has no Memory Firewall service configured. Set <Mono>MEMORY_FIREWALL_URL</Mono> and{" "}
        <Mono>MEMORY_FIREWALL_API_KEY</Mono> on the control plane (and the gateway, for the guardrail).
      </Notice>
    );
  if (!status.reachable)
    return (
      <Notice tone="warning">
        <p className="banner-title">The Memory Firewall service is unreachable</p>
        <p>
          {status.error ?? "No answer."} With Docker Compose, start it with{" "}
          <Mono>docker compose up -d --build memory-firewall</Mono>.
        </p>
      </Notice>
    );
  if (!status.ready || !status.service)
    return (
      <Notice tone="warning">
        <p className="banner-title">The Memory Firewall service is not ready</p>
        <p>{status.error ?? "Its signing keys or data directory are unavailable; see the service's logs."}</p>
      </Notice>
    );
  return null;
}

// ---- check memory ------------------------------------------------------------------------------

function InspectCard({ disabled, onDone }: { disabled: boolean; onDone: () => void }) {
  const { api } = useSession();
  const toast = useToast();
  const [items, setItems] = useState<MemoryItem[]>(SAMPLE_ITEMS);
  const [scan, setScan] = useState(true);
  const [problems, setProblems] = useState<string[]>([]);
  const [result, setResult] = useState<InspectResult | null>(null);
  const inspect = useAction((body: MemoryItem[], withScan: boolean) => api.memoryFirewallInspect(body, withScan));

  const update = (i: number, patch: Partial<MemoryItem>) =>
    setItems((all) => all.map((it, j) => (j === i ? { ...it, ...patch } : it)));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const errors = validateItems(items);
    setProblems(errors);
    if (errors.length) return;
    const out = await inspect.run(trimItems(items), scan);
    if (out) {
      setResult(out);
      toast("good", `${out.summary.admitted} admitted, ${out.summary.quarantined} quarantined`);
      onDone();
    }
  };

  return (
    <Card
      title="Check memory"
      actions={
        <Button size="sm" variant="ghost" onClick={() => (setItems(SAMPLE_ITEMS), setResult(null), setProblems([]))}>
          Load example
        </Button>
      }
    >
      <p className="muted">
        Each item goes through the writer gate and the source-trust rule; admitted items get a signed provenance
        record. This is real traffic for the service: it counts and logs every check (ids and reasons only, never the
        text).
      </p>
      <form className="stack section-gap" onSubmit={(e) => void submit(e)} noValidate>
        {items.map((it, i) => (
          <fieldset key={i} className="memory-item">
            <legend className="sr-only">Memory item {i + 1}</legend>
            <div className="form-row">
              <Field label="Id" htmlFor={`mf-id-${i}`}>
                <input id={`mf-id-${i}`} className="input" value={it.id} onChange={(e) => update(i, { id: e.target.value })} />
              </Field>
              <Field label="Source" htmlFor={`mf-src-${i}`}>
                <select id={`mf-src-${i}`} className="select" value={it.source} onChange={(e) => update(i, { source: e.target.value })}>
                  {MEMORY_SOURCES.map((src) => (
                    <option key={src}>{src}</option>
                  ))}
                </select>
              </Field>
              <Field label="Writer" htmlFor={`mf-writer-${i}`}>
                <input id={`mf-writer-${i}`} className="input" value={it.writer} onChange={(e) => update(i, { writer: e.target.value })} />
              </Field>
            </div>
            <Field label="Text" htmlFor={`mf-text-${i}`}>
              <textarea id={`mf-text-${i}`} className="textarea" rows={2} value={it.text} onChange={(e) => update(i, { text: e.target.value })} />
            </Field>
            <div className="row memory-item-footer">
              <label className="check">
                <input type="checkbox" checked={it.authorized} onChange={(e) => update(i, { authorized: e.target.checked })} />
                Written by an authorized writer
              </label>
              <Button
                size="sm"
                variant="ghost"
                icon={<IconTrash size={14} />}
                aria-label={`Remove memory item ${i + 1}`}
                onClick={() => setItems((all) => all.filter((_, j) => j !== i))}
              >
                Remove
              </Button>
            </div>
          </fieldset>
        ))}
        <div className="row">
          <Button size="sm" icon={<IconPlus size={14} />} onClick={() => setItems((all) => [...all, blankItem(all)])}>
            Add item
          </Button>
          <label className="check">
            <input type="checkbox" checked={scan} onChange={(e) => setScan(e.target.checked)} />
            Also scan the text for injected instructions
          </label>
        </div>
        {problems.length > 0 && (
          <Notice tone="warning">
            <ul className="banner-list">
              {problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </Notice>
        )}
        <ErrorBanner error={inspect.error} title="Check failed" />
        <div>
          <Button type="submit" variant="primary" busy={inspect.busy} disabled={disabled || items.length === 0}>
            Check memory
          </Button>
        </div>
      </form>
      {result && <InspectResults result={result} />}
    </Card>
  );
}

function InspectResults({ result }: { result: InspectResult }) {
  const { summary } = result;
  return (
    <div className="section-gap">
      <p className="row">
        <strong>Result</strong>
        <Badge tone="good">{`${summary.admitted} admitted`}</Badge>
        <Badge tone={summary.quarantined ? "critical" : "neutral"}>{`${summary.quarantined} quarantined`}</Badge>
        <Badge tone={summary.scan_flagged ? "warning" : "neutral"}>{`${summary.scan_flagged} flagged`}</Badge>
        <span className="muted">signed with key <Mono>{result.key_id}</Mono></span>
      </p>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Item</th>
              <th scope="col">Verdict</th>
              <th scope="col">Why</th>
              <th scope="col">Scan</th>
            </tr>
          </thead>
          <tbody>
            {result.results.map((v) => {
              const view = verdictView(v);
              return (
                <tr key={v.id}>
                  <td>
                    <Mono>{v.id}</Mono>
                    <span className="cell-sub">
                      {v.source} · {v.writer}
                    </span>
                  </td>
                  <td>
                    <Badge tone={view.tone}>{view.label}</Badge>
                  </td>
                  <td>
                    {view.detail}
                    {v.signature && <span className="cell-sub">signature <Mono>{v.signature.slice(0, 16)}…</Mono></span>}
                  </td>
                  <td>
                    {v.scan_findings.length === 0 ? (
                      <span className="muted">clean</span>
                    ) : (
                      v.scan_findings.map((f) => (
                        <span key={f} className="tag">
                          {scanLabel(f)}
                        </span>
                      ))
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ---- checkpoint self-test ---------------------------------------------------------------------

function SelfTestCard({ disabled, onDone }: { disabled: boolean; onDone: () => void }) {
  const { api } = useSession();
  const toast = useToast();
  const [result, setResult] = useState<SelfTestResult | null>(null);
  const run = useAction(() => api.memoryFirewallSelfTest());

  return (
    <Card
      title="Checkpoint integrity self-test"
      actions={
        <Button
          variant="primary"
          size="sm"
          busy={run.busy}
          disabled={disabled}
          onClick={async () => {
            const out = await run.run();
            if (out) {
              setResult(out);
              toast(out.passed ? "good" : "critical", `Self-test: ${out.guard_blocked} of ${out.attacks} attacks blocked`);
              onDone();
            }
          }}
        >
          Run self-test
        </Button>
      }
    >
      <p className="muted">
        Runs the library's five storage attacks on a scratch checkpoint database inside the service: each one edits the
        database directly, then reopens the agent. Shown for unprotected storage, the framework's built-in encryption
        and the Memory Firewall's signed checkpoints.
      </p>
      <ErrorBanner error={run.error} title="Self-test failed" />
      {run.busy && <Loading label="Running five attacks against three storage modes" />}
      {result && !run.busy && <SelfTestTable result={result} />}
    </Card>
  );
}

function SelfTestTable({ result }: { result: SelfTestResult }) {
  const rows = selfTestMatrix(result);
  return (
    <div className="section-gap">
      <p className="row">
        <Badge tone={result.passed ? "good" : "critical"}>
          {result.passed ? "passed" : "failed"}
        </Badge>
        <span>
          Memory Firewall blocked {result.guard_blocked} of {result.attacks} attacks
        </span>
        <span className="muted">· {ms(result.duration_ms)} · {dateTime(result.finished_at)}</span>
      </p>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Attack</th>
              {result.modes.map((m) => (
                <th key={m} scope="col">
                  {MODE_LABEL[m] ?? m}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.attack}>
                <td>{r.attack}</td>
                {result.modes.map((m) => {
                  const outcome = r.cells[m];
                  const view = outcome ? OUTCOME_VIEW[outcome] : null;
                  return (
                    <td key={m}>{view ? <Badge tone={view.tone}>{view.label}</Badge> : <span className="muted">—</span>}</td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted section-gap">
        Blocked: loading the tampered memory failed closed. Succeeded: the agent's decision changed without an error.
      </p>
    </div>
  );
}

// ---- event log ----------------------------------------------------------------------------------

function EventLogCard({ revision }: { revision: number }) {
  const { api } = useSession();
  const now = useNow(30_000);
  const events = useResource(() => api.memoryFirewallEvents(50), [api], 15_000);
  const { reload } = events;
  useEffect(() => {
    if (revision > 0) void reload();
  }, [revision, reload]);
  return (
    <Card flush title="Event log" actions={<span className="muted">newest 50 · ids and reasons only</span>}>
      <ErrorBanner error={events.error} />
      {events.data === undefined ? (
        events.error ? null : <Loading />
      ) : events.data.events.length === 0 ? (
        <EmptyState title="No events yet">Writes, rejections and quarantines appear here as memory is checked.</EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table table-compact">
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">Event</th>
                <th scope="col">Memory</th>
                <th scope="col">Writer or source</th>
                <th scope="col">Reason</th>
              </tr>
            </thead>
            <tbody>
              {events.data.events.map((e, i) => (
                <tr key={`${e.ts}-${e.event}-${i}`}>
                  <td className="num muted" title={dateTime(e.ts)}>
                    {relativeTime(e.ts, now)}
                  </td>
                  <td>
                    <Badge tone={eventTone(e.event)}>{e.event}</Badge>
                  </td>
                  <td>
                    <Mono>{e.checkpoint_id ?? "—"}</Mono>
                  </td>
                  <td>{e.thread_id}</td>
                  <td>
                    {e.reason ?? <span className="muted">—</span>}
                    {e.mitre && <span className="cell-sub">MITRE ATLAS {e.mitre}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
