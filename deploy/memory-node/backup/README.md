# PostgreSQL 17 encrypted physical recovery

This deployment provides continuous encrypted WAL archival, a daily verified
physical base backup, chain-aware retention, and an isolated PITR preparation
path. PostgreSQL remains authoritative. Nothing here starts a restored server,
enables an application service, or restores credentials into service.

The objective is a 15-minute RPO and four-hour RTO. Operators must measure those
objectives on the installed system; repository tests do not prove them.

## Fixed trust and storage boundary

The helper has no environment-controlled paths. Its installed contract is:

| Purpose | Exact path |
|---|---|
| PostgreSQL tools | `/usr/lib/postgresql/17/bin` |
| Canonical cluster | `/var/lib/postgresql/17/main` |
| independently mounted backup filesystem | `/mnt/memory-backup` |
| controlled plaintext staging mount | `/mnt/memory-backup-staging` |
| encrypted store | `/mnt/memory-backup/kivra-memory-postgres` |
| isolated recovery filesystem | `/mnt/memory-recovery` |
| public age recipient | `/etc/kivra-memory/backup-age-recipient` |
| recovery-only private identity | `/etc/kivra-memory/backup-age-identity` |

All three mount points must be real mount points, not directories on `/`. Create the
backup mount as `root:kivra-backup` mode `0750`. Create the store and `base`
as `memory-backup:kivra-backup` mode `2750`; create `wal`, `status`, and
`.staging` as `memory-backup:kivra-backup` mode `2770` (setgid). Create
`verification` as `memory-recovery:kivra-backup` mode `2750`. Encrypted objects
and content-free metadata are mode `0640`. Add only `memory-backup`, `postgres`, and the isolated
`memory-recovery` identity to `kivra-backup`; confirm those exact memberships
before activation. Plaintext staging remains mode `0600/0700`. Do not grant
`kivra-backup` to any application, ingress, worker, exporter, or monitoring
identity.

Create the isolated recovery mount as `root:memory-recovery` mode `0770`. The
fixed staging mount is a distinct, local controlled filesystem owned by
`memory-backup:memory-backup` mode `0700`. It must not be an offsite/NAS/cloud
destination. `pg_basebackup` and `pg_verifybackup` use a unique child there;
only the resulting age ciphertext and encrypted recovery manifest are written
to the backup failure domain. The child is removed on handled success/failure.
After power loss, inspect and remove only a positively identified valid-ID
staging child before retrying.

The split is deliberate: PostgreSQL needs group write only to publish WAL
objects and status through `.staging`; it must not be able to replace retained
base objects or the store root. `memory-backup` alone owns base generation and
retention. The recovery identity receives `kivra-backup` as a supplementary
group for read/traversal, with write access only to the exact status and
verification-marker directories granted by its verification unit.

The routine node contains only the public age recipient. Keep the private age
identity in an independent custody boundary and install it owned by the
dedicated `memory-recovery` identity as mode `0600` only on an isolated recovery
host. Run prepared PostgreSQL under that same non-root drill identity so its
bounded `restore_command` can decrypt WAL. Do not enable the verification timer
on the routine node. A concrete offsite mount, recipient, custody owner,
retention policy, and isolated recovery destination are mandatory before
activation.

The helper never accepts a database URL, destination root, binary directory, or
recipient through ambient environment variables. It emits fixed event/result
codes and bounded object identifiers only. Each object has an age-encrypted
full recovery manifest containing hashes, PostgreSQL system/timeline/LSN
metadata, migration and release revisions, and timestamps. Its minimal
plaintext `index.json` contains only the object identifier, kind, creation time,
verification state when applicable, and encrypted-manifest digest. A WAL index
also carries plaintext and ciphertext SHA-256 values so a routine node with no
private recovery identity can verify byte-identical archive retries. Neither
contains statements, evidence, authorization values, host coordinates, or
credentials.

## Provisioning and activation order

1. Create the independently mounted backup and controlled local staging
   filesystems and every fixed store child with the exact ownership and modes
   above. The helper will not create or repair these trusted roots.
2. Install `kivra-memory-postgres-backup` at
   `/usr/local/libexec/kivra-memory-postgres-backup`, owned by root and not
   writable by its service identity.
3. Generate the recovery identity outside the routine node. Install only its
   single public `age1...` recipient at the fixed recipient path. Replace the
   example placeholder; the helper deliberately rejects it.
4. Install a protected pgpass systemd credential for `memory_backup`. Create a
   PostgreSQL role with `LOGIN REPLICATION`, grant only `CONNECT` and `SELECT`
   on `alembic_version`, and do not grant application mutation privileges.
5. Write the exact deployed release revision to
   `/opt/kivra-memory/app/REVISION`. Write a SHA-256 of the reviewed,
   secret-free recovery configuration manifest to
   `/etc/kivra-memory/recovery-configuration.sha256`.
6. Exercise age encrypt/decrypt and atomic publication using synthetic bytes on
   both failure domains and the staging mount. Inject interruption, destination loss, read-only
   remount, ENOSPC, and wrong-identity failures; no final object may appear.
7. Merge `postgresql.conf.example` and `pg_hba.conf.example`, reload, force
   `pg_switch_wal()`, and confirm a complete encrypted WAL object appears.
8. Enable and run the base-backup service once. A base is published only after
   `pg_verifybackup` succeeds on plaintext staging and age encryption completes.
9. On the isolated recovery host, install the identity and run `verify latest`.
10. Perform PITR and validate content-free state before enabling monitoring and
    retention. Only then enable the base-backup and retention timers.

Never enable retention until a base plus its continuous WAL chain has restored
successfully. Archive failure can fill `pg_wal`; stop and investigate rather
than disabling archival or deleting WAL.

## Commands

Routine node commands are fixed systemd entry points:

```text
kivra-memory-postgres-backup archive-wal ABSOLUTE_SOURCE WAL_NAME
kivra-memory-postgres-backup base-backup
kivra-memory-postgres-backup retain
```

The first two publish an encrypted object directory by exclusive creation,
fsync, and an atomic same-filesystem rename. An identical WAL retry succeeds
only when the plaintext hash, ciphertext hash, manifest name, and on-disk bytes
agree; any mismatch fails closed. Recovery later decrypts and authenticates the
full manifest before trusting its bindings. Plain staging is removed on handled failure.
After an uncatchable process or host failure, inspect `.staging` without reading
payloads, preserve evidence, and remove only a positively identified stale
`base-<valid-id>` or `wal-<valid-name>-<nonce>` child before retrying.

On the isolated recovery host:

```text
kivra-memory-postgres-backup verify BACKUP_ID
kivra-memory-postgres-backup verify latest
kivra-memory-postgres-backup prepare-restore BACKUP_ID \
  /mnt/memory-recovery/DRILL_NAME --target-name RESTORE_POINT
```

`--target-time` requires an explicit UTC ISO 8601 value; `--target-lsn` requires
an uppercase PostgreSQL LSN. The destination must be one new or empty mode-0700
direct child of the recovery mount. Canonical storage, nested paths, symlinks,
existing data, unsafe archive members, wrong PostgreSQL major, damaged
ciphertext, failed authentication, and digest mismatch are rejected. The
helper extracts safely, reruns `pg_verifybackup`, writes recovery settings with
`recovery_target_action='pause'`, and creates `recovery.signal`. It does not
start PostgreSQL.

Before starting an isolated cluster, prove the canonical application units,
workers, ingress, tunnel, poller, and exporter are stopped and disabled; use a
private Unix socket and no TCP listeners. Start PostgreSQL 17 manually under a
dedicated drill identity, wait for recovery to pause, and prove the selected
content-free aggregates and hashes. Review and rotate credentials after any
rollback. Destroy decrypted drill data after recording content-free evidence.

## Retention invariant

Daily retention considers only bases whose encrypted-manifest digest has a
matching marker written by the isolated recovery identity after successful
decrypt and post-decrypt `pg_verifybackup`. It keeps at least the newest such
verified backup from each of eight UTC days plus the newest verified backup
from each of five ISO weeks. It always keeps the newest verified base and
refuses to run when no verified base exists. Unverified bases are preserved for
investigation and never treated as retention-eligible.
An exact WAL dependency watermark is external recovery state. Until a verified
watermark covering every retained chain and hold exists, automated retention
keeps every WAL segment, backup-history file, and timeline-history file. The
helper bounds obsolete base generations only and honors a regular, bounded
`HOLD` marker inside a base object. This conservative rule requires
operator-reviewed WAL-capacity management, but cannot infer a dependency and
delete the last known verified chain.

Status files under `status/` are atomic, content-free fixed-field JSON. They are
operational hints, not canonical state or proof of offsite durability. A real
restore is the proof.

## Stop conditions

Stop immediately if the backup mount disappears, WAL backlog threatens
canonical capacity, the last verified chain could be pruned, restore resolves
outside the isolated mount, the recovery identity is present on the routine
node, authentication or checksum verification fails, or services/listeners are
active on the recovery node. Preserve names, fixed result codes, hashes, and
timestamps only; never preserve payloads or secret-bearing command output.
