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
   prune backups, or restart competing writers to hide divergence.
5. Record evidence according to the [content-free template](evidence-template.md).

## Index

| Event | Runbook |
|---|---|
| Routine base backup, verification, retention, or legal/erasure hold | [Backup operations](backup-operations.md) |
| WAL archive backlog or failure | [WAL failure](wal-failure.md) |
| Planned stop or dependency-safe start | [Shutdown and startup](shutdown-startup.md) |
| Release deployment or source/database rollback | [Upgrade and rollback](upgrade-rollback.md) |
| Queue depth, age, lease, or worker failure | [Queue diagnosis](queue-diagnosis.md) |
| Archive head, signature, signer, host key, or remote divergence | [Archive divergence](archive-divergence.md) |
| Alert, outage, suspected compromise, or privacy event | [Incident and alert response](incident-alerts.md) |
| PostgreSQL point-in-time recovery | [PostgreSQL PITR](postgresql-pitr.md) |
| Recovery from the primary Forgejo archive | [Forgejo recovery](forgejo-recovery.md) |
| Recovery from the encrypted secondary Git bundle | [Secondary-bundle recovery](secondary-bundle-recovery.md) |
| NPM edit/upgrade or external-exposure alarm | [NPM drift](npm-drift.md) |
| Recovery-drill teardown and evidence review | [Drill cleanup](drill-cleanup.md) |
| Installed service, timer, listener, and artifact audit | [Installed-system verification](installed-verification.md) |
| Credential rotation or compromise | [Credential lifecycle](credentials.md) |

## Common hard stops

Stop, keep writers/listeners disabled where applicable, and preserve
content-free evidence if identity or installation binding is unknown; a
recovery target is active; backup/WAL continuity is incomplete; an archive
anchor, signature, host key, or signer is unexpected; a destruction tombstone
would be rolled back; or any diagnostic contains payload or credential data.
