# Operations runbooks

These runbooks apply to the accepted private single-owner topology. Run them
from a protected operator session with least privilege. Replace placeholders
from the protected installation inventory; never paste secret-bearing commands
or output into repository files.

## Before any change

1. Identify the intended release, installation, service set, and failure
   domain without displaying private coordinates or credentials.
2. Capture the applicable root-local report through
   `kivra-memory-operator-report@<report-id>.service` and confirm the latest
   separate bounded recovery status. A report is diagnostic evidence, not
   proof that a restore works.
3. Declare the stop condition, rollback point, write-disable boundary, and
   cleanup target.
4. Preserve an unexpected state before remediation. Do not rewrite archives,
   delete any recovery object under the M10 no-prune posture, or restart
   competing writers to hide divergence.
5. Record evidence according to the [content-free template](evidence-template.md).

## Index

| Event | Runbook |
|---|---|
| Routine base backup, verification, retention, or legal/erasure hold | [Backup operations](backup-operations.md) |
| WAL archive backlog or failure | [WAL failure](wal-failure.md) |
| Planned stop or dependency-safe start | [Shutdown and startup](shutdown-startup.md) |
| Release deployment or source/database rollback | [Upgrade and rollback](upgrade-rollback.md) |
| Queue depth, age, lease, or worker failure | [Queue diagnosis](queue-diagnosis.md) |
| Future Forgejo archive/remote divergence (excluded from M10) | [Archive divergence](archive-divergence.md) |
| Alert, outage, suspected compromise, or privacy event | [Incident and alert response](incident-alerts.md) |
| PostgreSQL point-in-time recovery | [PostgreSQL PITR](postgresql-pitr.md) |
| Backup-aware synthetic hard-forget recovery | [Hard-forget recovery](hard-forget-recovery.md) |
| M10 recovery from the encrypted local Git bundle | [Secondary-bundle recovery](secondary-bundle-recovery.md) |
| Future Forgejo provider recovery (excluded from M10) | [Forgejo recovery](forgejo-recovery.md) |
| NPM edit/upgrade or external-exposure alarm | [NPM drift](npm-drift.md) |
| Recovery-drill teardown and evidence review | [Drill cleanup](drill-cleanup.md) |
| Installed service, timer, listener, and artifact audit | [Installed-system verification](installed-verification.md) |
| Credential rotation or compromise | [Credential lifecycle](credentials.md) |

## Common hard stops

Stop, keep writers/listeners disabled where applicable, and preserve
content-free evidence if identity or installation binding is unknown; a
recovery target is active; backup/WAL continuity is incomplete; a local signed-
history anchor, signature, or signer is unexpected; a destruction tombstone
would be rolled back; or any diagnostic contains payload or credential data.
Forgejo host-key and remote checks apply only to the future Forgejo runbooks,
not M10 closeout.
