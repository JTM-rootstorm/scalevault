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

The absolute configuration pins the local verified repository, exact branch,
external expected head, application/Alembic compatibility, and gap-free signer
epochs. Review its fixed content-free JSON result, transfer the ciphertext plus
its content-free sidecar to the separate failure domain, and remove plaintext
scratch before reporting success. Do not record the recipient or protected
configuration contents as evidence.

The recovery identity and encryption private key never accompany the bundle.
The secondary process must not push, merge, amend, tag, or create a semantic
checkpoint.

Any sealed-key backup must exclude the destruction ledger. Backing up keys and
their destruction authority as one rollback-able object would permit a stale
backup to resurrect a destroyed DEK.

## Retention

Run retention only after verification and offsite-copy success:

```bash
systemctl start kivra-memory-backup-retention.service
systemctl show kivra-memory-backup-retention.service -p Result -p ExecMainStatus
```

Retention must preserve the last complete verified base-backup/WAL chain, the
declared recovery window, current legal/incident holds, and every backup needed
to test destruction dominance. A failed backup or copy extends retention; it
never authorizes pruning. A legal or erasure hold changes eligibility only
through the reviewed hold mechanism and must remain content free.

## Completion

Confirm timers are enabled as intended, no `.staging` object remains, status
files parse canonically, no private recovery identity exists on the routine
node, and the operator report shows current primary and offsite ages. Schedule
an isolated [PITR drill](postgresql-pitr.md); backup verification alone is not
restore acceptance.
