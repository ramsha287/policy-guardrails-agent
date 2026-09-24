// Human review UI for ESCALATE decisions (plan section 7). Reviewers see pending items for their
// tenant with the reason, guardrail, risk score and a redacted preview, then approve or reject.
// The raw payload is only shown to reviewer-raw keys, and every view and decision is audited by
// the control plane. Items expire after REVIEW_TTL_MINUTES; an expired item means BLOCK.

import { useEffect, useRef, useState, type ReactNode } from "react";

import { IconEye } from "../components/icons";
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
  Notice,
  PageHeader,
  ReviewStatusBadge,
  Segmented,
  Toolbar,
} from "../components/ui";
import { countdown, dateTime, relativeTime, secondsLeft, shortId } from "../lib/format";
import { useAction, useNow, useResource } from "../lib/hooks";
import { useQueryParam, useRoute } from "../lib/router";
import { useSession } from "../lib/session";
import type { Review, ReviewStatus } from "../lib/types";

type Filter = ReviewStatus | "all";

export function riskTone(score: number): "critical" | "serious" | "warning" | "neutral" {
  if (score >= 80) return "critical";
  if (score >= 60) return "serious";
  if (score >= 40) return "warning";
  return "neutral";
}

function Countdown({ expiresAt, now }: { expiresAt: string; now: number }) {
  const left = secondsLeft(expiresAt, now);
  return (
    <span className={left < 120 ? "countdown countdown-urgent" : "countdown"} title={`Expires ${dateTime(expiresAt)}`}>
      {countdown(expiresAt, now)}
    </span>
  );
}

export function ReviewsPage() {
  const { api, me } = useSession();
  const route = useRoute();
  const [status, setStatus] = useQueryParam(route, "status");
  const [selectedId, setSelectedId] = useQueryParam(route, "id");
  const [tenant, setTenant] = useQueryParam(route, "tenant");
  const filter = (status || "pending") as Filter;
  const now = useNow(1000);

  const reviews = useResource(
    () => api.reviews({ status: filter === "all" ? "" : filter, tenant_id: tenant || undefined }),
    [api, filter, tenant],
    filter === "pending" ? 5_000 : 30_000,
  );
  const tenants = useResource(() => (me.platform ? api.tenants() : Promise.resolve([])), [api]);

  const rows = reviews.data ?? [];
  return (
    <>
      <PageHeader
        title="Review queue"
        description={
          <>
            Requests a guardrail escalated to a person. The agent waits for your decision; anything not decided within{" "}
            {me.review_ttl_minutes} minutes is blocked.
          </>
        }
      />
      <Toolbar>
        <Segmented<Filter>
          label="Status"
          value={filter}
          onChange={(v) => {
            setStatus(v === "pending" ? null : v);
          }}
          options={[
            { value: "pending", label: "Pending" },
            { value: "approved", label: "Approved" },
            { value: "rejected", label: "Rejected" },
            { value: "expired", label: "Expired" },
            { value: "all", label: "All" },
          ]}
        />
        {me.platform && (
          <select
            className="select select-auto"
            aria-label="Tenant"
            value={tenant}
            onChange={(e) => setTenant(e.target.value || null)}
          >
            <option value="">All tenants</option>
            {(tenants.data ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.id})
              </option>
            ))}
          </select>
        )}
      </Toolbar>
      <ErrorBanner error={reviews.error} />
      <div className="split">
        <Card flush title={`${rows.length} ${filter === "all" ? "" : filter} item${rows.length === 1 ? "" : "s"}`}>
          {reviews.data === undefined ? (
            <Loading />
          ) : rows.length === 0 ? (
            <EmptyState title={filter === "pending" ? "Nothing waiting for review" : "No items"}>
              {filter === "pending" && "Escalated requests appear here as soon as a guardrail holds one."}
            </EmptyState>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">{filter === "pending" ? "Time left" : "Status"}</th>
                    <th scope="col">Guardrail</th>
                    <th scope="col">Agent</th>
                    <th scope="col" className="num">
                      Risk
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr
                      key={r.id}
                      className={r.id === selectedId ? "clickable selected" : "clickable"}
                      onClick={() => setSelectedId(r.id)}
                    >
                      <td>
                        {r.status === "pending" ? <Countdown expiresAt={r.expires_at} now={now} /> : <ReviewStatusBadge status={r.status} />}
                        <span className="cell-sub">{relativeTime(r.created_at, now)}</span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="link-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedId(r.id);
                          }}
                        >
                          {r.guardrail_id}
                        </button>
                        <span className="cell-sub">
                          {r.stage} · {r.environment}
                        </span>
                      </td>
                      <td>
                        {r.agent_id}
                        <span className="cell-sub">{r.tenant_id}</span>
                      </td>
                      <td className="num">
                        <Badge tone={riskTone(r.risk_score)} icon={false}>
                          {r.risk_score}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        {selectedId ? (
          <ScrollIntoViewOnNarrow key={selectedId}>
            <ReviewDetail
              id={selectedId}
              now={now}
              onDecided={() => void reviews.reload()}
              onClose={() => setSelectedId(null)}
            />
          </ScrollIntoViewOnNarrow>
        ) : (
          <Card className="detail-placeholder">
            <EmptyState title="Select an item">Pick a request on the left to see why it was held.</EmptyState>
          </Card>
        )}
      </div>
    </>
  );
}

/** On narrow screens the detail renders below the list; bring it into view when an item is picked. */
function ScrollIntoViewOnNarrow({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (window.matchMedia("(max-width: 1100px)").matches) ref.current?.scrollIntoView({ block: "start" });
  }, []);
  return <div ref={ref}>{children}</div>;
}

function ReviewDetail({
  id,
  now,
  onDecided,
  onClose,
}: {
  id: string;
  now: number;
  onDecided: () => void;
  onClose: () => void;
}) {
  const { api, can } = useSession();
  const toast = useToast();
  // Loaded once per selection: each detail view is recorded in the audit log, so no polling here.
  const detail = useResource(() => api.review(id), [api, id]);
  const [note, setNote] = useState("");
  const [raw, setRaw] = useState<Review["payload"]>(undefined);
  const [confirmRaw, setConfirmRaw] = useState(false);

  const decide = useAction(async (approve: boolean) => {
    const updated = await api.decideReview(id, approve, note.trim());
    toast("good", approve ? "Approved: the agent can continue." : "Rejected: the request stays blocked.");
    setNote("");
    onDecided();
    await detail.reload();
    return updated;
  });
  const reveal = useAction(async () => {
    const withRaw = await api.review(id, true);
    setRaw(withRaw.payload ?? null);
    setConfirmRaw(false);
  });

  if (detail.error) {
    return (
      <Card title="Review">
        <ErrorBanner error={detail.error} />
        <Button onClick={onClose}>Close</Button>
      </Card>
    );
  }
  const r = detail.data;
  if (!r) {
    return (
      <Card title="Review">
        <Loading />
      </Card>
    );
  }
  const expired = r.status === "pending" && secondsLeft(r.expires_at, now) <= 0;
  const status: ReviewStatus = expired ? "expired" : r.status;
  const canDecide = can("reviews:decide") && status === "pending";

  return (
    <Card
      title={
        <span className="row">
          Review <Mono>{shortId(r.id)}</Mono> <ReviewStatusBadge status={status} />
        </span>
      }
      actions={
        <Button size="sm" variant="ghost" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="stack">
        {status === "pending" && (
          <Notice tone="warning">
            The agent is waiting. Time left: <Countdown expiresAt={r.expires_at} now={now} />. If nobody decides, the
            request is blocked.
          </Notice>
        )}
        <div>
          <p className="field-label">Why it was held</p>
          <p>{r.reason}</p>
        </div>
        <KeyValue
          items={[
            ["Guardrail", <Mono key="g">{r.guardrail_id}</Mono>],
            ["Stage", `${r.stage} (${r.environment})`],
            ["Agent", `${r.agent_id} · tenant ${r.tenant_id}`],
            ["Risk score", <Badge key="r" tone={riskTone(r.risk_score)} icon={false}>{r.risk_score}</Badge>],
            ["Request ID", <Mono key="q">{r.request_id}</Mono>],
            ["Held", `${dateTime(r.created_at)} (${relativeTime(r.created_at, now)})`],
            ...(r.reviewer
              ? ([
                  ["Decided by", `${r.reviewer}, ${dateTime(r.decided_at)}`],
                  ["Note", r.decision_note || "—"],
                ] as [string, string][])
              : []),
            ...(r.raw_viewed_by.length > 0
              ? ([["Raw viewed by", r.raw_viewed_by.join(", ")]] as [string, string][])
              : []),
          ]}
        />
        <div>
          <p className="field-label">Preview (redacted)</p>
          <div className="preview">{r.preview || "No preview available."}</div>
        </div>

        {can("reviews:raw") && (
          <div>
            {raw === undefined ? (
              <Button size="sm" icon={<IconEye size={14} />} onClick={() => setConfirmRaw(true)}>
                Show raw payload
              </Button>
            ) : (
              <>
                <p className="field-label">Raw payload</p>
                <Json value={raw} maxHeight="md" />
              </>
            )}
            <ErrorBanner error={reveal.error} />
          </div>
        )}

        {canDecide && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
            }}
          >
            <Field label="Note" htmlFor="review-note" hint="Sent back to the agent with your decision and kept in the audit log.">
              <textarea
                id="review-note"
                className="textarea"
                rows={3}
                maxLength={1000}
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Why you approved or rejected it"
              />
            </Field>
            <ErrorBanner error={decide.error} />
            <div className="row">
              <Button variant="primary" busy={decide.busy} onClick={() => void decide.run(true)}>
                Approve
              </Button>
              <Button variant="danger" busy={decide.busy} onClick={() => void decide.run(false)}>
                Reject
              </Button>
            </div>
          </form>
        )}
        {!can("reviews:decide") && status === "pending" && (
          <p className="muted">Your key can view reviews but not decide them.</p>
        )}
      </div>

      <Dialog
        open={confirmRaw}
        title="Show the raw payload?"
        onClose={() => setConfirmRaw(false)}
        footer={
          <>
            <Button onClick={() => setConfirmRaw(false)}>Cancel</Button>
            <Button variant="primary" busy={reveal.busy} onClick={() => void reveal.run()}>
              Show it
            </Button>
          </>
        }
      >
        <p>
          The raw payload can contain the personal data the guardrail was protecting. Your name is recorded against this
          review when you open it.
        </p>
      </Dialog>
    </Card>
  );
}
