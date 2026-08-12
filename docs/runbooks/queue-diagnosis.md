# Queue diagnosis

Use fixed-label metrics and the root-local operator report first. Diagnose one
queue class at a time: embedding/outbox, archive export, GitHub ingress,
lifecycle, sealed purge, or backup.

1. Record queue class, bounded depth/age bucket, worker result, and first
   observed time. Do not list job payloads or identifiers.
2. Confirm the responsible service is enabled only when intended, active, on
   the accepted release, connected to the local database, and using its exact
   least-privilege role.
3. Check readiness of dependencies: mounts and digest-pinned embedding bundle,
   Forgejo/host key, GitHub installation, sealed key provider, or backup store.
4. Compare oldest age, lease-expiry counts, attempts bucket, dead-letter count,
   and throughput. Broad SQL dumps and raw exception logging are prohibited.
5. Correct the dependency or configuration cause. Let normal lease expiry and
   idempotent handlers recover work; do not edit queue rows, reset attempts,
   duplicate a job, or run multiple exporter instances.
6. Prove age and depth fall, the high-water mark advances monotonically, and
   no fixed failure counter continues increasing.

Stop workers before investigating repeated deterministic failures, signature
or archive divergence, destruction-state conflict, payload-canary detection,
or a lease that would permit competing durable work. Preserve the failing job
in place and escalate through [Incident response](incident-alerts.md).
