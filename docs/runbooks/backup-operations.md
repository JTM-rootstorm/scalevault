# Backup operations

This procedure covers routine PostgreSQL physical backups, verification, local
encrypted archive bundles, and validation-only retention. It does not prove
recovery until the corresponding isolated restore drill passes. PBS protection
and Backblaze upload are operator-managed outside this procedure and are not
M10 acceptance gates.

## Preconditions

- `/mnt/memory-backup` is the exact dedicated backup mount and is not the
  canonical data failure domain.
- The routine node contains only the public age recipient at
  `/etc/kivra-memory/backup-age-recipient`; the recovery private identity is
  absent.
- PostgreSQL WAL archiving uses
  `/usr/local/libexec/kivra-memory-postgres-backup archive-wal` and the latest
  status reports a complete chain.
- The external local signed-history anchor is independently available when a
  bundle is produced.
- Content-key backups explicitly exclude the independent root-owned destruction
  ledger at `/var/lib/kivra-memory-sealed/destruction-ledger`; that ledger has
  its own protected, monotonic preservation path.

Stop if the mount is absent, the private recovery identity is present, WAL is
missing, a prior verification failed, the archive diverged, or the operator
cannot identify the last complete chain.

## Base backup and verification

```bash
# Routine node
systemctl start kivra-memory-base-backup.service
systemctl show kivra-memory-base-backup.service -p Result -p ExecMainStatus

# Isolated recovery host, after the backup store is available there
systemctl start kivra-memory-backup-verify.service
systemctl show kivra-memory-backup-verify.service -p Result -p ExecMainStatus
```

Verification needs the separately held private identity and therefore runs on
the isolated recovery host; the routine node's verification timer remains
disabled. Review canonical JSON below
`/mnt/memory-backup/kivra-memory-postgres/status/`. Record only the bounded
object identifier, timestamps, digests, counts, and fixed reason/result codes.
Never copy an environment, database URL, WAL contents, or encryption material.

## Local encrypted archive bundle

Use the protected local archive repository and independently held trust
configuration. Verify its exact head against the external rollback anchor,
complete first-parent signed history, manifests, schemas, hashes, and bounds.
Only then create a complete Git bundle and encrypted object through the
recovery CLI:

```bash
kivra-memory-archive-recovery --config /absolute/recovery.json \
  bundle-create --destination /absolute/local-bundle-staging/object.age \
  --scratch-directory /absolute/protected-scratch --recipient '<AGE_RECIPIENT>'
```

The absolute configuration pins the archive target, local verified repository,
exact branch, external expected head, final manifest digest, high-water
sequence, application/Alembic compatibility, signer public keys/fingerprints,
gap-free epochs, transition records and both detached signatures, and any
compromised-signer cutoff. Review its fixed content-free JSON result, transfer
the ciphertext plus its content-free sidecar to the separate failure domain,
and remove plaintext scratch before reporting success. Do not record the
recipient or protected configuration contents as evidence.

For M10, materialize the accepted bundle and restore it into a freshly migrated
empty database at the exact same head, manifest, high-water mark, signer policy,
and object bytes as the local signed-history proof. Wrong-identity and corrupt-
ciphertext negatives plus cleanup are required. No cadence, remote equality,
remote promotion, archive continuation, or exporter append is claimed.

The recovery identity and encryption private key never accompany the bundle.
The bundle process must not push, merge, amend, tag, or create a semantic
checkpoint. Transfer, freshness, retention, retrieval, and deletion at
Backblaze are operator-managed and are not inspected here.

Any sealed-key backup must exclude the destruction ledger. Backing up keys and
their destruction authority as one rollback-able object would permit a stale
backup to resurrect a destroyed DEK.

## Retention validation; pruning blocked

Run the validator after the local backup inventory and completed objects have
been verified:

```bash
systemctl start kivra-memory-backup-retention.service
systemctl show kivra-memory-backup-retention.service -p Result -p ExecMainStatus
```

The checked-in command intentionally deletes nothing. Its expected fixed result
is `no_prune_dependency_watermark_absent`. Record bounded counts and canonical
inventory digests for bases, WAL/history, restore points, holds, verification
markers, manifests/indexes, and status artifacts before and after it. Require
exact equality except for the explicitly expected new content-free validation
status artifact. Decrypt plus `pg_verifybackup` does not prove an actual PITR
start/target, and M10 grants no deletion authority. The eight-daily/five-weekly
policy is an accumulation and inventory floor, not a deletion target or an
elapsed-time acceptance delay.

Every base, WAL segment, backup-history file, timeline-history file, restore
point, and hold remains retained throughout M10. Malformed, missing, corrupt, or
ambiguous inventory fails closed. Capacity pressure is a stop condition and
never authorizes manual pruning or an inferred dependency graph. Any future
deletion requires a new accepted architecture decision defining authenticated,
fresh, replay-safe deletion evidence and the complete dependency/hold graph.
Routine sealed-key-provider backup activation remains independent and requires
restore reconciliation against the current separately held destruction ledger
anchor.

## Completion

Confirm only approved timers are enabled, no `.staging` object remains, status
files parse canonically, no private recovery identity exists on the routine
node, and bounded status shows the current local primary age and no-prune
capacity headroom. Schedule an isolated
[PITR drill](postgresql-pitr.md); backup verification alone is not restore
acceptance.
