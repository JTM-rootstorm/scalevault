# Backup operations

This procedure covers routine PostgreSQL physical backups, verification,
secondary archive copies, and retention. It does not prove recovery until the
corresponding isolated restore drill passes.

## Preconditions

- `/mnt/memory-backup` is the exact dedicated backup mount and is not the
  canonical data failure domain.
- The routine node contains only the public age recipient at
  `/etc/kivra-memory/backup-age-recipient`; the recovery private identity is
  absent.
- PostgreSQL WAL archiving uses
  `/usr/local/libexec/kivra-memory-postgres-backup archive-wal` and the latest
  status reports a complete chain.
- The external archive anchor and offsite target are independently available.
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

## Secondary archive copy

Use the dedicated read-only recovery identity and pinned Forgejo host key.
Verify the already-pushed remote head against the external rollback anchor,
complete first-parent signed history, manifests, schemas, hashes, and bounds.
Only then create a complete Git bundle and encrypted object through the
recovery CLI:

```bash
kivra-memory-archive-recovery --config /absolute/recovery.json \
  bundle-create --destination /absolute/offsite-staging/object.age \
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

Create one secondary bundle for each newly accepted pushed head; jobs may
coalesce while one is running, but the next object must use the newest accepted
head. An accepted head without a verified bundle for more than one hour alerts.
Materialize and clean-restore a bundle at least monthly.

The recovery identity and encryption private key never accompany the bundle.
The secondary process must not push, merge, amend, tag, or create a semantic
checkpoint.

Any sealed-key backup must exclude the destruction ledger. Backing up keys and
their destruction authority as one rollback-able object would permit a stale
backup to resurrect a destroyed DEK.

## Retention validation; pruning blocked

Run the validator only after verification and offsite-copy success:

```bash
systemctl start kivra-memory-backup-retention.service
systemctl show kivra-memory-backup-retention.service -p Result -p ExecMainStatus
```

The checked-in command intentionally deletes nothing. Its expected fixed result
is `no_prune_dependency_watermark_absent`. Decrypt plus `pg_verifybackup` does
not prove an actual PITR start/target, and the repository has no authenticated
base/WAL/timeline/restore-point dependency-and-hold catalog that can authorize
deletion. The eight-daily/five-weekly policy is an activation target, not
current deletion authority.

Until that trust contract and a real isolated PostgreSQL 17 PITR proof exist,
every base, WAL segment, backup-history file, timeline-history file, restore
point, and hold remains potentially required. A failed backup or copy extends
retention; capacity pressure is a stop condition and never authorizes manual
pruning. Routine sealed-key-provider backup activation is independently blocked
until its manifests bind an externally fresh, separately held destruction
ledger anchor and restore reconciliation passes.

## Completion

Confirm only approved timers are enabled, no `.staging` object remains, status
files parse canonically, no private recovery identity exists on the routine
node, and bounded status shows current primary and offsite ages. Schedule
an isolated [PITR drill](postgresql-pitr.md); backup verification alone is not
restore acceptance.
