# Upgrade and rollback

## Upgrade

1. Record the accepted source commit, signature state, package locks, current
   Alembic head, installed unit digests, and latest verified recovery objects.
2. Review release notes for migrations, shared contracts, systemd policy,
   credential changes, backup compatibility, and signer transitions.
3. Run repository verification and the required PostgreSQL 17 gate. Validate
   installed candidate units with `systemd-analyze verify`; review
   `systemd-analyze security` as evidence, not a numeric pass/fail oracle.
4. Create and independently verify a fresh physical recovery chain and archive
   head before maintenance.
5. Enter the [safe shutdown](shutdown-startup.md) boundary. Install immutable
   artifacts and configuration without modifying credential values.
6. Run migrations once with the dedicated migration role. Never let runtime
   services own or opportunistically apply schema changes.
7. Start in dependency order. Verify readiness, queue progress, archive
   continuity, alerts, log canaries, and both access paths before closing the
   window.

## Rollback decision

Application rollback is allowed only when its database compatibility range
includes the current schema and archive format. A destructive/down migration or
database PITR is a recovery event, not an ordinary package rollback.

If the release can run on the current schema, stop external access and writers,
restore the prior immutable application/configuration artifacts, revalidate
units, and restart in order. Do not roll back credential revocations, signer
transitions, destruction tombstones, or external rollback anchors.

If database PITR is required, leave the canonical installation disabled and
follow [PostgreSQL PITR](postgresql-pitr.md) into an isolated destination.
Review every credential and destruction action newer than the target before
any recovered service starts. Never overlay the production cluster or point an
older exporter at newer Forgejo history.
