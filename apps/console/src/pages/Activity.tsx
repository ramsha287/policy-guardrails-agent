// The control plane's append-only change log: who changed what, with before/after.

import { useState } from "react";

import { Card, EmptyState, ErrorBanner, Json, Loading, Mono, PageHeader, Toolbar } from "../components/ui";
import { dateTime } from "../lib/format";
import { useResource } from "../lib/hooks";
import { useQueryParam, useRoute } from "../lib/router";
import { useSession } from "../lib/session";
import type { Change } from "../lib/types";

const ENTITIES = ["", "snapshot", "publish_request", "assignment", "guardrail_version", "tenant", "api_key", "agent", "action", "modifier", "review", "admin_key"];

export function ActivityPage() {
  const { api } = useSession();
  const route = useRoute();
  const [entity, setEntity] = useQueryParam(route, "entity");
  const [limit, setLimit] = useState(100);
  const changes = useResource(() => api.changes({ entity: entity || undefined, limit }), [api, entity, limit], 30_000);
  const [open, setOpen] = useState<Change | null>(null);
  return (
    <>
      <PageHeader title="Activity log" description="Every change to the pipeline, catalog, reviews and keys. The log can't be edited." />
      <Toolbar>
        <select className="select select-auto" aria-label="Entity" value={entity} onChange={(e) => setEntity(e.target.value || null)}>
          {ENTITIES.map((e) => (
            <option key={e} value={e}>
              {e ? e.replace(/_/g, " ") : "Everything"}
            </option>
          ))}
        </select>
      </Toolbar>
      <ErrorBanner error={changes.error} />
      <Card flush>
        {changes.data === undefined ? (
          <Loading />
        ) : changes.data.length === 0 ? (
          <EmptyState title="Nothing logged" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Change</th>
                  <th scope="col">Who</th>
                  <th scope="col">
                    <span className="sr-only">Details</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {changes.data.map((c) => (
                  <tr key={`${c.id}-${c.at}`}>
                    <td>{dateTime(c.at)}</td>
                    <td>
                      <strong>{c.action}</strong> {c.entity.replace(/_/g, " ")} <Mono>{c.entity_id}</Mono>
                    </td>
                    <td>{c.actor}</td>
                    <td className="num">
                      {(c.before || c.after) && (
                        <button type="button" className="link-btn" onClick={() => setOpen(open?.id === c.id ? null : c)}>
                          {open?.id === c.id ? "Hide" : "Details"}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {open && (
        <Card title={`${open.action} ${open.entity} ${open.entity_id}`}>
          <div className="diff-grid">
            <div className="diff-side">
              <h3>Before</h3>
              {open.before ? <Json value={open.before} maxHeight="md" /> : <p className="muted">—</p>}
            </div>
            <div className="diff-side">
              <h3>After</h3>
              {open.after ? <Json value={open.after} maxHeight="md" /> : <p className="muted">—</p>}
            </div>
          </div>
        </Card>
      )}
      {changes.data && changes.data.length >= limit && limit < 1000 && (
        <div className="row section-gap">
          <button type="button" className="btn btn-secondary" onClick={() => setLimit((l) => Math.min(1000, l + 200))}>
            Load more
          </button>
        </div>
      )}
    </>
  );
}
