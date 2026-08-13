# Installed-system verification

Repository tests do not prove the installed LXC, NPM, PostgreSQL recovery
store, or active provider state. Run this checklist after installation,
upgrade, recovery, and at final M10 acceptance. Forgejo provider state and
Backblaze/PBS evidence are outside the M10 gate and must not be inferred from
this checklist.

## Read-only inventory

- record accepted release and migration revision, exact enabled/disabled unit
  set, timer schedules, service users, credential names, executable and unit
  digests, required mounts, and listener address classes;
- confirm relay, node-agent, OAuth, public plugin/submission, and generic
  third-party enrollment services are absent or disabled;
- confirm canonical API/PostgreSQL/operator surfaces are local only and Codex
  ingress is the exact private port 8443 listener behind NPM;
- confirm the routine node lacks the backup recovery private identity.

## Service and recovery checks

Run `systemd-analyze verify` for every installed candidate and review hardening
with `systemd-analyze security`. Verify service credentials appear only through
their intended `/run/credentials` namespace, core dumps are disabled as
designed, and journal retention matches policy. Confirm base-backup, verify,
monitoring, and report units have fixed bounded output. The retention helper
must report `no_prune_dependency_watermark_absent` and delete nothing; any
destructive-pruning claim is an activation blocker.

Verify migration `0011_observability_aggregates` and the exact least-privilege
database boundary:

- `kivra_memory_metrics` is a `LOGIN NOINHERIT` wrapper that can SET only the
  `NOLOGIN NOINHERIT` `kivra_memory_observability` capability;
- that capability has no table or sequence privileges and can execute only
  `scalevault_observability_snapshot(uuid)`;
- `kivra_memory_operator_report_login` can SET only
  `kivra_memory_operator_report`, whose only data access is the reviewed
  fixed-shape report functions; and
- `PUBLIC` cannot execute any of those functions, while direct table reads and
  arbitrary tenant access fail for both wrapper/capability pairs.

Verify `kivra-memory-metrics-exporter.service` runs as
`memory-metrics:memory-metrics`, accepts only its local dedicated database and
UUIDv7 tenant credentials, binds exactly `127.0.0.1:9098`, refreshes every 30
seconds with a 10-second query timeout, and clears DB-derived samples while
setting `kivra_memory_database_collector_up=0` on failure. Prometheus must use
the `scalevault-database-metrics` job. Verify the distinct
`scalevault-postgresql` job scrapes its loopback exporter at exactly
`127.0.0.1:9187`; this supplies the PostgreSQL-up series and must not expose
payload or replace the bounded ScaleVault collector.

Generate a report through a fresh
`kivra-memory-operator-report@<report-id>.service` instance. Verify it accepts
only its dedicated local login and per-instance tenant credential, creates one
new mode-`0600` file below `/var/lib/kivra-memory/operator-reports`, and emits
no report contents to stdout or the journal.

Verify PostgreSQL 17 durability/WAL settings and recovery-chain freshness,
the exact local signed-history external head anchor, alert rule evaluation,
fixed-label Prometheus output, root-only report access,
and content-free journal/NPM/metric/artifact canary scans. Confirm
`/var/lib/kivra-memory-sealed/destruction-ledger` is root-owned, group
`kivra-destruction-ledger`, mode `2770`; only the dedicated destruction broker
can write it, API/ingress/purge consumers have only their intended read/request
access, and content-key backups exclude it. Verify the independently retained
freshness anchor matches or is monotonically extended before reactivation.

Operational journal/alert history may not exceed 30 days; content-free
recovery/acceptance reports may not exceed 400 days. Both need explicit
operator-chosen byte caps. Missing caps leave installed retention pending.
External alert delivery is not required for M10.

Apply the complete [NPM drift gate](npm-drift.md), active-provider revocation
gates when provisioned, the installed [PITR](postgresql-pitr.md) drill, local
signed-history restoration, the
[hard-forget recovery](hard-forget-recovery.md) drill bound to the exact
provider-backup inventory, base backup, WAL window, recovery target, and
synthetic ciphertext correlation, and the
[secondary-bundle](secondary-bundle-recovery.md) clean database restore bound
to the exact same head, manifest, high-water mark, signer policy, and object
bytes. Record required categories as `pass`, `fail`, or `pending`; absence of
evidence is `pending`, never `pass`.

Record Forgejo provider restore, remote promotion, archive continuation, and
exporter append as `excluded / not evaluated`. Record Backblaze/PBS provider
evidence and external alert delivery as `non-blocking / not evaluated` unless
the operator separately supplies evidence. None may be reported as passed from
local source or test evidence.

The NPM static checker must return its exact content-free JSON success object
with bounded configuration counts. Prose output, a partial generated
configuration, or a zero process status without the expected result object is
not acceptance evidence.

For every candidate public artifact, run `kivra-memory-scan-public-artifact`
with independently supplied synthetic canaries. Preserve only `ok`, the
artifact digest, and fixed counts. A pass proves this bounded offline scan; it
does not authorize or accept a public export or publication workflow.

For the cross-process gate, capture only the exact approved operational outputs
as root-owned regular mode-`0400` or mode-`0600` files. List their absolute
paths, one per line, in a root-owned mode-`0600` file and run:

```bash
kivra-memory-scan-operational-canaries \
  --artifact-list /absolute/root-owned-mode-0600-list \
  --canary-file /absolute/root-owned-mode-0600-canaries
```

Accept only exit zero with `ok=true`, `result=clean`, and fixed
`bytes_scanned`, `inputs_scanned`, and `matches=0` counts. `match` and
`incomplete` fail closed. Preserve no path or matching content in evidence.

Use the [evidence template](evidence-template.md). Do not attach raw unit files,
environment, generated NPM configuration, Prometheus dumps, journal exports, or
provider responses to the acceptance record.
