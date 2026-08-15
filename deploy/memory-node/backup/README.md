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
| Canonical cluster | `/mnt/memory/kivra-memory/postgresql/17/main` |
| only mounted storage root | `/mnt/memory` |
| encrypted store | `/mnt/memory/kivra-memory/backups/postgresql-pitr` |
| routine-node plaintext staging | `/var/lib/kivra-memory/backup-staging` |
| isolated recovery-host plaintext | `/var/lib/kivra-memory/recovery` |
| public age recipient | `/etc/kivra-memory/backup-age-recipient` |
| recovery-only private identity | `/etc/kivra-memory/backup-age-identity` |

`/mnt/memory` is the only mount in this topology; the store is a directory
beneath it, not an independent backup mount or failure domain. Create the store
and `base` as `memory-backup:kivra-backup` mode `2750`; create `wal`, `status`,
and `.staging` as `memory-backup:kivra-backup` mode `2770` (setgid). Create
`verification` as `memory-recovery:kivra-backup` mode `2750`. Encrypted objects
and content-free metadata are mode `0640`. Add only `memory-backup`, `postgres`,
and the isolated `memory-recovery` identity to `kivra-backup`; confirm those
exact memberships before activation. Plaintext staging remains mode `0600/0700`.
Do not grant `kivra-backup` to any application, ingress, worker, exporter, or
monitoring identity.

Provision the locked, non-login `memory-recovery` system identity and the
`verification` directory on the routine node even though the private age
identity and verification timer remain absent there. Base backup, WAL archive,
and retention validate this ownership but cannot write the recovery-owned
directory. On the isolated recovery host, the same named identity writes only
digest-bound verification markers; `memory-backup` reads them through
`kivra-backup` and cannot replace them.

The routine staging directory is `/var/lib/kivra-memory/backup-staging`, owned
by `memory-backup:memory-backup` mode `0700`; it is not a mount. The isolated
recovery-host plaintext root is `/var/lib/kivra-memory/recovery`, owned by
`memory-recovery:memory-recovery` mode `0700`; it too is not a mount.
`pg_basebackup` and `pg_verifybackup` use a unique staging child. Only the
resulting age ciphertext and encrypted recovery manifest are written beneath
the encrypted store. Remove that child on handled success or failure. After a
power loss, inspect and remove only a positively identified valid-ID staging
child before retrying.

This is a same-NAS, same-dataset, and same-capacity fate arrangement: the
canonical cluster and encrypted backup store share `/mnt/memory`. It does not
claim independent local durability or an independent local failure domain.
Nightly NAS backups and any operator-managed Backblaze or PBS protection are
outside this deployment contract and are not claimed or accepted here.

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
on the routine node. The exact encrypted-store directory, recipient, custody
owner, no-prune capacity policy, and isolated local recovery destination are
mandatory before activation. No additional or offsite mount is required by
this deployment contract.

Install the public recipient as `root:kivra-backup` mode `0640`. Install the
immutable release-tree `REVISION` as `root:root` mode `0444`, and the mutable
`recovery-configuration.sha256` deployment metadata as `root:root` mode
`0644`. They must contain only their single bounded revision or digest value.
The helper validates these owners and modes before use.

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

1. Verify the existing `/mnt/memory` mount, then create the fixed store
   children and the two local plaintext directory roots with the exact
   ownership and modes above. The helper will not create or repair these
   trusted roots.
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
6. Exercise age encrypt/decrypt and atomic publication using synthetic bytes in
   the store and staging directory. Inject interruption, destination loss,
   read-only remount, ENOSPC, and wrong-identity failures; no final object may
   appear.
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

WAL source bytes are opened descriptor-relative beneath the exact `pg_wal`
directory with `O_NOFOLLOW`; one stable descriptor is streamed to age while its
hash is computed, and before/after inode metadata must match. Duplicate retries
also require and hash-check the encrypted recovery manifest.

Base-backup tar creation traverses descriptor-relative sorted names, never
follows links, verifies stable inode metadata, and normalizes owner, group,
mode, time, and PAX metadata. Restore scans the complete archive before writing:
at most 200,000 members, 2 TiB per member, 8 TiB expanded bytes, 32 path
components, 4,096 path bytes, and 255 bytes per component. Sparse files, links,
devices, duplicate paths, file-as-parent paths, unsafe names, truncation, and a
changed archive fail closed before or during bounded extraction.
After an uncatchable process or host failure, inspect `.staging` without reading
payloads, preserve evidence, and remove only a positively identified stale
`base-<valid-id>` or `wal-<valid-name>-<nonce>` child before retrying.

On the isolated recovery host, use the installed helper to verify a selected
backup (or `latest`) and prepare exactly one target selector. `--target-time`
requires an explicit UTC ISO 8601 value; `--target-lsn` requires an uppercase
PostgreSQL LSN. The destination must be one new or empty mode-0700 direct child
of `/var/lib/kivra-memory/recovery`, never a path below `/mnt/memory`.
Canonical storage, nested paths, symlinks, existing data, unsafe archive
members, wrong PostgreSQL major, damaged ciphertext, failed authentication, and
digest mismatch are rejected. The helper extracts safely, reruns
`pg_verifybackup`, writes recovery settings with `recovery_target_action='pause'`,
and creates `recovery.signal`. It does not start PostgreSQL.

The recovery host may receive the same NAS dataset with accepted base/WAL
objects read-only and writes limited to the exact `status` and `verification`
marker directories. The recovery process must have no traversal or read access
to the canonical subtree, and every restore output stays outside `/mnt/memory`.

Before starting an isolated cluster, prove the canonical application units,
workers, ingress, tunnel, poller, and exporter are stopped and disabled; use a
private Unix socket and no TCP listeners. Start PostgreSQL 17 manually under a
dedicated drill identity, wait for recovery to pause, and prove the selected
content-free aggregates and hashes. Review and rotate credentials after any
rollback. Destroy decrypted drill data after recording content-free evidence.

## Retention invariant

The checked-in retention command is intentionally validation-only and deletes
nothing. A decrypt plus `pg_verifybackup` marker does not prove that PostgreSQL
actually started, reached a requested PITR target, or consumed a complete WAL
chain. An authenticated production PITR result and exact base/WAL/timeline/
restore-point dependency-and-hold catalog do not yet exist. Consequently every
base, WAL segment, backup-history file, timeline-history file, restore point,
and hold remains potentially required. The command validates names, manifests,
markers, and holds, then reports `no_prune_dependency_watermark_absent`.

The retention unit mounts the store read-only except for `status/`. It rejects
staging residue, unexpected store children or object members, links and special
files, malformed base/WAL indexes, ciphertext digest mismatches, malformed or
orphaned verification markers, invalid JSON inventory hints, and malformed hold
files. A run is bounded to 200,000 structural entries. It records counts and
canonical SHA-256 inventory digests separately for base objects, WAL/history
objects, restore-point artifacts, holds, verification markers,
indexes/manifests, and status artifacts. `latest-retention.json` is deliberately
excluded from the status-artifact digest because it is the command's sole
permitted mutation; operators compare that file's prior absence or digest
separately.

The same status records filesystem total, used, and available bytes plus store
apparent and allocated bytes. The validation fails closed below the installed
critical capacity floor of 10 percent free. The warning remains 20 percent free
under the monitoring rules, leaving an operator response window without giving
retention any prune authority.

The public age recipient does not authenticate the producer of a drill record:
any holder of that public value can create ciphertext for the recovery identity.
ADR 0027 does not define a recovery-evidence signing identity, allowed signer,
rollback anchor, or operator-attested catalog format, and the archive signing
key has a separate authority that must not be reused here. Repository-generated
or merely age-encrypted `PITR-VERIFIED`, dependency, restore-point, or hold files
therefore cannot authorize deletion. Activation requires an accepted trust
contract plus content-free evidence from an actual isolated PostgreSQL 17 PITR
run; repository tests and `pg_verifybackup` alone are insufficient.

The eight-daily/five-weekly policy is an activation target, not deletion
authority. Implementing it requires the authenticated dependency catalog and
real isolated-start/PITR proof first. Capacity pressure is a stop condition;
operators must not manually approximate dependencies and prune around this
gate.

Status files under `status/` are atomic, content-free fixed-field JSON. They are
operational hints, not canonical state or proof of offsite durability. A real
restore is the proof.

## Stop conditions

Stop immediately if `/mnt/memory` disappears, the shared dataset lacks capacity,
WAL backlog threatens canonical capacity, the last verified chain could be
pruned, restore resolves below `/mnt/memory`, the recovery identity is present
on the routine node, authentication or checksum verification fails, or
services/listeners are active on the recovery node. Preserve names, fixed result
codes, hashes, and timestamps only; never preserve payloads or secret-bearing
command output.
