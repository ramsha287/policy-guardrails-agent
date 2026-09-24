// Two-person publishing: a publish or rollback in a protected environment waits here until a
// different admin key approves it. A request goes stale if another version is published first, so
// nobody approves a diff they did not see.

import { useState, type ReactNode } from "react";

import { useToast } from "../components/toast";
import {
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
  RequestStatusBadge,
  Segmented,
  Toolbar,
} from "../components/ui";
import { dateTime, relativeTime } from "../lib/format";
import { useAction, useResource } from "../lib/hooks";
import { useQueryParam, useRoute } from "../lib/router";
import { useSession } from "../lib/session";
import type { Assignment, PublishRequest } from "../lib/types";
import { DiffEntry } from "./Pipeline";

export function diffAssignments(base: Assignment[], next: Assignment[]) {
  const a = new Map(base.map((x) => [x.id, x]));
  const b = new Map(next.map((x) => [x.id, x]));
  const out: { id: string; kind: "added" | "removed" | "changed"; live: Assignment | null; working: Assignment | null }[] = [];
  for (const [id, w] of b) {
    const l = a.get(id);
    if (!l) out.push({ id, kind: "added", live: null, working: w });
    else if (JSON.stringify(l) !== JSON.stringify(w)) out.push({ id, kind: "changed", live: l, working: w });
  }
  for (const [id, l] of a) if (!b.has(id)) out.push({ id, kind: "removed", live: l, working: null });
  return out.sort((x, y) => x.id.localeCompare(y.id));
}

export function ApprovalsPage() {
  const { api } = useSession();
  const route = useRoute();
  const [statusParam, setStatus] = useQueryParam(route, "status");
  const status = statusParam || "pending";
  const requests = useResource(
    () => api.publishRequests({ status: status === "all" ? "" : status }),
    [api, status],
    status === "pending" ? 10_000 : undefined,
  );
  return (
    <>
      <PageHeader
        title="Publish approvals"
        description="Publishes and rollbacks in protected environments need a second admin key. You can't approve your own request."
      />
      <Toolbar>
        <Segmented
          label="Status"
          value={status}
          onChange={(v) => setStatus(v === "pending" ? null : v)}
          options={[
            { value: "pending", label: "Pending" },
            { value: "approved", label: "Approved" },
            { value: "rejected", label: "Rejected" },
            { value: "stale", label: "Stale" },
            { value: "expired", label: "Expired" },
            { value: "all", label: "All" },
          ]}
        />
      </Toolbar>
      <ErrorBanner error={requests.error} />
      {requests.data === undefined ? (
        <Loading />
      ) : requests.data.length === 0 ? (
        <Card>
          <EmptyState title={status === "pending" ? "No requests waiting" : "No requests"} />
        </Card>
      ) : (
        <div className="stack">
          {requests.data.map((r) => (
            <RequestCard key={r.id} request={r} onDecided={() => void requests.reload()} />
          ))}
        </div>
      )}
    </>
  );
}

function RequestCard({ request: r, onDecided }: { request: PublishRequest; onDecided: () => void }) {
  const { api, me, can } = useSession();
  const toast = useToast();
  const [open, setOpen] = useState(r.status === "pending");
  const [note, setNote] = useState("");
  const base = useResource(
    () =>
      open && r.base_version ? api.snapshot(r.environment, r.base_version) : Promise.resolve(undefined),
    [api, open, r.environment, r.base_version],
  );
  const decide = useAction(async (approve: boolean) => {
    await api.decidePublishRequest(r.id, approve, note.trim());
    toast("good", approve ? `Approved: ${r.environment} is updated.` : "Request rejected.");
    onDecided();
  });
  const own = r.requested_by_key === me.key_id;
  const changes =
    open && r.document && (base.data || !r.base_version)
      ? diffAssignments(base.data?.document?.assignments ?? [], r.document.assignments)
      : null;

  return (
    <Card
      title={
        <span className="row">
          {r.kind === "rollback" ? "Rollback" : "Publish"} to {r.environment} <RequestStatusBadge status={r.status} />
        </span>
      }
      actions={
        <Button size="sm" variant="ghost" onClick={() => setOpen((v) => !v)}>
          {open ? "Hide details" : "Show details"}
        </Button>
      }
    >
      <KeyValue
        items={[
          ["Requested by", `${r.requested_by}, ${relativeTime(r.requested_at)}`],
          ["Note", r.note || "—"],
          ["Based on", <Mono key="b">{r.base_version ?? "nothing published"}</Mono>],
          ...(r.rolled_back_from ? ([["Restores", <Mono key="rb">{r.rolled_back_from}</Mono>]] as [string, ReactNode][]) : []),
          ...(r.decided_by
            ? ([
                ["Decided by", `${r.decided_by}, ${dateTime(r.decided_at)}`],
                ["Decision note", r.decision_note || "—"],
              ] as [string, ReactNode][])
            : []),
          ...(r.published_version ? ([["Published as", <Mono key="p">{r.published_version}</Mono>]] as [string, ReactNode][]) : []),
        ]}
      />
      {open && (
        <div className="stack section-gap">
          <ErrorBanner error={base.error} />
          {changes === null ? (
            <Loading label="Loading the diff" />
          ) : changes.length === 0 ? (
            <Notice>No assignment changes compared with the base version.</Notice>
          ) : (
            changes.map((c) => <DiffEntry key={c.id} {...c} />)
          )}
          {r.status === "pending" && can("publish:approve") && (
            <>
              {own ? (
                <Notice tone="warning">You requested this publish, so a different admin key has to approve it.</Notice>
              ) : (
                <>
                  <Field label="Note" htmlFor={`note-${r.id}`}>
                    <input
                      id={`note-${r.id}`}
                      className="input"
                      value={note}
                      maxLength={1000}
                      onChange={(e) => setNote(e.target.value)}
                    />
                  </Field>
                  <ErrorBanner error={decide.error} title="Not decided" />
                  <div className="row">
                    <Button variant="primary" busy={decide.busy} onClick={() => void decide.run(true)}>
                      Approve and publish
                    </Button>
                    <Button variant="danger" busy={decide.busy} onClick={() => void decide.run(false)}>
                      Reject
                    </Button>
                  </div>
                </>
              )}
            </>
          )}
        </div>
      )}
    </Card>
  );
}
