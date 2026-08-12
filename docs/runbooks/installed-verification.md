# Installed-system verification

Repository tests do not prove the installed LXC, NPM, PostgreSQL, Forgejo,
offsite copy, or provider state. Run this checklist after installation,
upgrade, recovery, and at final M10 acceptance.

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
retention, monitoring, and report timers/services have fixed bounded output.

Verify PostgreSQL 17 durability/WAL settings and recovery-chain freshness,
Forgejo pinned host key and external head anchor, encrypted offsite copy age,
alert rules/delivery, fixed-label Prometheus output, root-only report access,
and content-free journal/NPM/metric/artifact canary scans. Confirm
`/var/lib/kivra-memory-sealed/destruction-ledger` is root-owned, group
`kivra-destruction-ledger`, mode `2770`; only the intended API/purge services
have write access, and content-key backups exclude it.

Apply the complete [NPM drift gate](npm-drift.md), provider revocation gates
when provisioned, and separate [PITR](postgresql-pitr.md),
[Forgejo](forgejo-recovery.md), and
[secondary-bundle](secondary-bundle-recovery.md) drills. Record each category
as `pass`, `fail`, `pending`, or `not-applicable`; absence of evidence is
`pending`, never `pass`.

For every candidate public artifact, run `kivra-memory-scan-public-artifact`
with independently supplied synthetic canaries. Preserve only `ok`, the
artifact digest, and fixed counts. A pass proves this bounded offline scan; it
does not authorize or accept a public export or publication workflow.

Use the [evidence template](evidence-template.md). Do not attach raw unit files,
environment, generated NPM configuration, Prometheus dumps, journal exports, or
provider responses to the acceptance record.
