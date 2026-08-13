# PostgreSQL point-in-time recovery

This procedure restores PostgreSQL 17 into `/mnt/memory-recovery`. It never
overlays `/mnt/memory` or an active production cluster.

Run an isolated PITR drill at least monthly and a full physical/Forgejo/bundle/
credential/destruction exercise at least quarterly. Measure the 15-minute RPO
and four-hour RTO objectives; do not infer them from backup completion.

## Prepare

1. Select a verified base-backup object and a target name, time, or LSN within
   its complete WAL chain. Record safe identifiers and digests only.
2. Keep API, ingress, tunnel, workers, pollers, and exporter disabled on the
   recovery node. Prove the destination is disposable, empty, on the exact
   recovery mount, and cannot bind production listeners.
3. Supply `/etc/kivra-memory/backup-age-identity` through the restricted
   recovery process. It must not have been stored with the backup or present on
   a routine backup node.
4. Confirm PostgreSQL 17 binaries, extensions, accepted release, migration
   compatibility, storage capacity, external archive anchor, credential
   inventory, and the current independent destruction ledger at
   `/var/lib/kivra-memory-sealed/destruction-ledger`.

Stop on a missing segment, unverifiable manifest, destination symlink or
nonempty path, wrong system identifier, incompatible release, or unknown
destruction state.

## Restore and replay

Use the installed helper with exactly one target selector:

```bash
/usr/local/libexec/kivra-memory-postgres-backup prepare-restore \
  <BACKUP_ID> /mnt/memory-recovery --target-time <RFC3339_TARGET>
```

The generated PostgreSQL recovery configuration must use the helper's
`restore-wal` operation, a local-only socket/port, and the selected target with
the reviewed inclusive/exclusive policy. Start only the isolated PostgreSQL
instance. Never start a ScaleVault application service during replay.

## Verify

Confirm recovery reached the selected target and timeline, then verify system
identifier, exact migration head, extensions, event/global sequence and hash
chains, projection high-water marks, aggregate counts/digests, archive prefix
relationship, and synthetic canary result codes. Rebuild projections and
requeue/rebuild embeddings through supported commands in the isolated system.

Compare all post-target credential revocations/rotations and key-destruction
actions against their external monotonic state. Preserve the current ledger,
construct the recovered key provider with it, and reconcile every restored key
backup before reads or workers run. A recovered credential row or DEK may not
authorize access merely because it exists at the older target.

## Finish

Record achieved recovery point and RPO/RTO, fixed verification results,
write-disable confirmation, credential reissue posture, and destruction
reconciliation. Unless the operator explicitly selects this recovery for a
separate promotion procedure, stop it and follow [Drill cleanup](drill-cleanup.md).
