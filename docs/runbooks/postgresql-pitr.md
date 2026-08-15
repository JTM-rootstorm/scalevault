# PostgreSQL point-in-time recovery

This procedure restores PostgreSQL 17 into one disposable direct child of
`/mnt/memory-recovery`. It never overlays `/mnt/memory`, an active production
cluster, or the recovery-mount root.

Run an isolated PITR drill at least monthly and the full physical,
credential/destruction, and local signed-history/bundle exercise at least
quarterly. Measure the 15-minute RPO and four-hour RTO objectives; do not infer
them from backup completion. Forgejo provider recovery and archive continuation
are not part of this exercise.

## Prepare

1. Use a dedicated isolated recovery host, not the routine Memory Node. Keep
   API, ingress, tunnel, workers, pollers, archive exporters, and destructive
   services absent or disabled. The canonical data mount must be absent.
2. Select a verified base-backup object and a target name, time, or LSN within
   its complete WAL chain. Record safe identifiers and digests only.
3. Prove `/mnt/memory-recovery` is a separate mount and that the named direct
   child is new or empty, mode `0700`, and disposable.
4. Supply `/etc/kivra-memory/backup-age-identity` only to the restricted
   recovery process. It must not have been stored with the backup or present on
   a routine backup node.
5. Confirm PostgreSQL 17 binaries, extensions, accepted release, migration
   compatibility, storage capacity, credential inventory, and the current
   independent destruction ledger at
   `/var/lib/kivra-memory-sealed/destruction-ledger`.

Stop on a missing segment, unverifiable manifest, destination symlink or
nonempty path, wrong system identifier, incompatible release, unknown
destruction state, active application process, canonical mount, or TCP
listener.

## Restore and replay

Choose a lower-case drill name matching `[a-z0-9][a-z0-9.-]{0,62}`. Use the
installed helper as `memory-recovery` with exactly one target selector. The
destination must be a direct child; `/mnt/memory-recovery` itself is invalid.

```bash
runuser --user memory-recovery -- \
  /usr/local/libexec/kivra-memory-postgres-backup prepare-restore \
  <BACKUP_ID> /mnt/memory-recovery/<DRILL_NAME> \
  --target-time <UTC_RFC3339_TARGET>
```

Review the generated recovery settings in place. Require the installed
helper's `restore-wal` operation, the exact selected target, and
`recovery_target_action='pause'`. The helper uses PostgreSQL's default
inclusive target policy. If an exclusive target is required, stop rather than
patching the generated configuration or replacing its `restore_command`.

After the recovered configuration and authentication inputs have been
reviewed, start PostgreSQL 17 under `memory-recovery` with an isolated Unix
socket, `listen_addresses=''`, and `archive_mode=off`. The checked PostgreSQL
17 `pg_ctl` option shape is below; this syntax check is not restore acceptance:

```bash
runuser --user memory-recovery -- /usr/lib/postgresql/17/bin/pg_ctl \
  --pgdata=/mnt/memory-recovery/<DRILL_NAME> \
  --log=/mnt/memory-recovery/<DRILL_NAME>-control/postgresql.log \
  --wait --timeout=60 \
  --options="-c listen_addresses='' \
    -c unix_socket_directories='/mnt/memory-recovery/<DRILL_NAME>-control' \
    -c unix_socket_permissions=0700 -c port=55432 -c archive_mode=off \
    -c logging_collector=off -c log_statement=none" \
  start
```

Pre-create the control directory as `memory-recovery:memory-recovery` mode
`0700`. Prove there is no TCP listener on port `55432`; the port only names the
private socket. Never start a ScaleVault application service during replay.

## Verify

Use only the reviewed content-free verifier bound to the selected Phase 2
manifest and synthetic fixture. It must confirm:

- the selected target and timeline, A and B present, and later C absent;
- system identifier, PostgreSQL 17, exact migration, and extension set;
- event/global sequence and hash-chain integrity;
- projection high-water marks and aggregate counts/digests;
- content-free recovery anchors and the Phase 2 synthetic correlation;
- credential review and current destruction-ledger reconciliation before any
  application read;
- supported offline projection rebuild and embedding requeue/rebuild behavior;
  and
- achieved recovery point, RPO/RTO, write-disable, and listener isolation.

If the reviewed verifier or a supported offline rebuild/requeue command is
unavailable, stop and leave the gate pending. Do not improvise payload-bearing
SQL or start API, worker, poller, or exporter services to manufacture evidence.
A live or current archive-exporter head is not required.

## Corruption negatives

Never corrupt an accepted encrypted base, WAL/history object, restore point,
hold, index, manifest, or verification marker. The repository test mutates
disposable fixtures; that is not a safe installed-store procedure.

For each live negative, create a separate, inventoried ciphertext-only copy of
the selected base object beneath `/mnt/memory-recovery`, without hard links.
Prove the pristine copy has the same bounded inventory digest as its accepted
source and shares no inode with it. Corrupt only the copied
`recovery-manifest.json.age` for the manifest case and only the copied
`backup.tar.age` for the ciphertext case. Never repair a corrupted copy in
place or use it for the positive restore.

Because the helper has a fixed store path, run negatives only after the
positive PostgreSQL instance is stopped. Unmount the accepted store from the
isolated host, bind the applicable drill-owned copy at `/mnt/memory-backup`,
remount that bind read-only, and verify the resolved source and mount options.
Require `manifest_ciphertext_digest_mismatch` or `ciphertext_digest_mismatch`
as applicable, nonzero exit, no published destination, and no change to the
accepted-store inventory. Remove the negative bind before reattaching the
accepted store read-only. Any mount ambiguity, shared source, hard link, or
accepted-object change fails the drill.

## Cleanup and evidence

Stop the isolated PostgreSQL instance, then follow
[Drill cleanup](drill-cleanup.md). Before deletion, approve and resolve the
exact data root, control root, negative-copy roots, negative output roots,
staged identity, socket, log, and scratch paths. Never use a wildcard,
unresolved variable, recovery-mount root, or accepted-store path as a cleanup
target.

The second check must prove no drill process, listener, mount user, negative
bind, plaintext, credential, socket, log, configuration, or copied ciphertext
remains; the private identity returned to independent custody; the accepted
base/WAL inventory digest is unchanged; and the routine node never received
the private identity.

Record only fixed verification/rejection codes, safe object/target values,
bounded counts and digests, elapsed time, RPO/RTO, write-disable and listener
results, credential/destruction posture, and cleanup/second-check results. Do
not retain SQL text, logs, complete generated configuration, raw database
output, payloads, credentials, or private coordinates.
