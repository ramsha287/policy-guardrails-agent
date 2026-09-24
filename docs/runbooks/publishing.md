# PublishWaitingForApproval

**What it means.** A production publish or rollback has waited more than 4 hours for a second
admin. Nothing is broken, but the change isn't live yet, and the request expires after
`controlPlane.publishRequestTtlHours` (24 h).

**Act.** A different admin opens **Publish approvals** in the console, reviews the field-level diff,
and approves or rejects it. If another version was published in the meantime, the request is
`stale` and has to be requested again: nobody approves a diff they didn't see.
