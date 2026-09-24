# AuditEventsDropped / AuditSpoolBacklog

**What it means.** Audit events couldn't be written to Postgres.
- **AuditSpoolBacklog** (warning): events are safe on the gateway's disk spool
  (`/var/cache/guardrail-gateway/audit-spool`) and are replayed automatically when Postgres
  accepts writes again.
- **AuditEventsDropped** (critical): the spool was full or unwritable too, so events were lost.
  Decisions still happened, but they are missing from the audit log. Treat this as a compliance
  incident.

**Check**

```bash
kubectl -n $NS logs deploy/$P-gateway -c gateway --since=30m | grep -i audit | tail -20
kubectl -n $NS exec deploy/$P-gateway -c gateway -- du -sh /var/cache/guardrail-gateway/audit-spool
```

**Common causes and fixes**

- *Postgres down or full*: fix Postgres. The spool drains within seconds afterwards
  (`audit_spool_bytes` goes to 0).
- *No partition for the current month* (insert error mentioning the partition): run the
  retention job by hand:
  `kubectl -n $NS create job --from=cronjob/$P-audit-retention audit-partitions-now`.
- *Spool full*: raise `gateway.audit.spoolSizeLimit` (emptyDir size), then fix the database.

**Note** The spool is an `emptyDir`. It survives container restarts but not pod deletion, so
don't delete gateway pods while `audit_spool_bytes > 0` unless you accept losing those events.
