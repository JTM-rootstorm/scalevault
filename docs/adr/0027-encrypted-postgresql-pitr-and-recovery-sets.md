# ADR 0027: Encrypted PostgreSQL PITR and recovery sets

- Status: Accepted
- Date: 2026-08-12
- Supersedes: None
- Extends: ADR 0007 and ADR 0015
- Amended by: ADR 0033 and ADR 0035

## Context

ADR 0007 requires controlled persistent storage and encrypted offsite recovery
copies. ADR 0015 provides an independently verifiable semantic archive, but it
is not a physical PostgreSQL backup and excludes credentials, key material,
derived data, deployment configuration, and exporter checkpoints. Logical dumps
used by earlier drills do not provide continuous point-in-time recovery.

Recovery must distinguish objects with different authorities rather than call
an intact database directory a safely reactivated ScaleVault node.

## Decision

### Objectives and physical recovery chain

The production recovery objectives are a 15-minute RPO and a four-hour RTO.
They are objectives measured by installed alerts and drills, not guarantees
inferred from a successful backup command.

PostgreSQL 17 uses continuous WAL archiving and one verified physical base
backup every day. A base backup is retention-eligible only after its PostgreSQL
backup manifest and checksums pass `pg_verifybackup`, every member is accounted
for, the required WAL range is present, and an isolated restore has established
the first usable chain. Routine validation must continue after activation; a
backup that has not completed verification is not a recovery point.

Backup and WAL helpers use fixed arguments, bounded names, exclusive temporary
objects on the destination filesystem, file and directory synchronization, and
atomic publication. A duplicate WAL name is accepted only when its bytes are
identical. Missing mounts, partial objects, mismatched duplicates, corruption,
authentication failure, or unavailable storage fail closed and never publish a
successful status.

The base-backup format is `pg_basebackup --format=plain --wal-method=stream
--manifest-checksums=SHA256` into private same-filesystem staging. It passes
`pg_verifybackup --no-parse-wal` before packaging. The verified directory is
encoded as one deterministic, path-sorted uncompressed POSIX tar archive with
normalized metadata and no links or special files, then published as one
`age`-encrypted `backup.tar.age`. Its full recovery manifest is a separate
`age`-encrypted `recovery-manifest.json.age`. The only plaintext catalog object
is a minimal `index.json` containing the opaque object identifier, creation
time, fixed verification state, and encrypted-manifest SHA-256. It contains no
database coordinates, LSN, timeline, paths, content sizes, or secret material.

Each WAL segment similarly publishes one encrypted `segment.age`, one
separately encrypted full recovery manifest, and one minimal plaintext index
under its strictly validated PostgreSQL WAL filename. Publication fsyncs a
complete staged object directory and renames it atomically on the same
filesystem. Restore authenticates and decrypts, verifies ciphertext and
plaintext bindings, extracts only through a bounded no-link path-safe reader,
and reruns `pg_verifybackup`. PostgreSQL/server-side and tar compression are not
used in this contract; changing format or compression requires compatibility
and resource-limit review.

The supported PITR targets are an exact PostgreSQL LSN, an unambiguous UTC
timestamp, or an exact named restore point. Recovery into an active data
directory, canonical storage, a non-empty destination, a different PostgreSQL
major version, or a destination with active writers is forbidden.

### Encryption and custody

Physical base backups, WAL segments, and their content-free recovery metadata
are encrypted with `age` before leaving the controlled recovery boundary. The
routine backup service receives only an explicit public recipient. Its matching
private identity is held independently of the Memory Node, NAS, backup job, and
encrypted recovery objects and is supplied only to an isolated recovery
environment.

The recipient, private-identity custodian, offsite destination, and disposable
restore location are required activation inputs. This ADR does not invent
operator identities, paths, hostnames, or destinations. A recipient transition
is versioned: retained objects remain associated with their original recipient
until they expire or are re-encrypted and reverified.

### Failure domains and retention

The canonical PostgreSQL data and live WAL on the controlled NAS are one
failure domain. Temporary local or NAS staging is not an independent copy. The
private Forgejo archive is a separately verifiable semantic recovery source,
not a PostgreSQL backup. Encrypted PostgreSQL chains and the encrypted archive
bundle defined by ADR 0029 must be published atomically into an operator-chosen
offsite failure domain that is independent of the canonical NAS and primary
Forgejo service.

Retention keeps at least eight verified daily chains and five verified weekly
chains. A chain consists of a verified base backup, all required WAL and
timeline history through its declared recovery interval, its authenticated
metadata, and its configuration bindings. Daily and weekly generations may
refer to the same physical chain when it satisfies both classes. Retention
never deletes:

- the last complete verified recovery chain;
- a base backup while retained WAL still depends on it;
- WAL needed by any retained chain or declared restore point; or
- an object under an explicit recovery, investigation, destruction-ledger, or
  operator hold.

If eligibility or dependency calculation is unavailable, corrupt, or
ambiguous, pruning stops. Capacity pressure raises an alert; it does not weaken
this rule.

### Recovery-set authority and bindings

Every published recovery set records content-free, authenticated bindings for
the PostgreSQL system identifier, source timeline, start and end LSN, required
timeline history, base-backup manifest checksum, encrypted-object checksums,
PostgreSQL major version, exact Alembic revision, source release identity, and
the digest of an operator-reviewed deployment configuration manifest. Exact
recovery status, verification results, retention state, drill results, and
external high-water anchors remain operational state outside the canonical
database being backed up.

The objects in a complete recovery procedure have these authorities:

| Object | Authority and restoration rule |
|---|---|
| Canonical PostgreSQL state | Semantic source of truth at the selected PITR point; restore only into an isolated destination. |
| Signed private archive | Independent semantic history verified under ADR 0015 and ADR 0029; never silently overrides a divergent database. |
| Sealed key-provider state | Separate confidential recovery object; usable only after ADR 0028 destruction reconciliation. |
| Monotonic destruction state | Separately rooted authority that always dominates restored key-provider material. |
| Digest-binding material | Separately restored exact identity; absence or mismatch disables sealed operations. |
| Archive verification anchors | Root-controlled public trust and rollback anchors; never learned from the archive. |
| Deployment configuration manifest | Reviewed compatibility input; it does not restore secrets or activate services. |
| Provider and service credentials | Reissued, reassociated, or reviewed outside database/archive restore. |
| Embeddings, indexes, and worker leases | Derived or ephemeral; rebuilt or requeued and never restored as authority. |

Recovery sources are considered only after their own integrity and rollback
anchors validate. A usable physical chain is preferred for PITR because it
preserves exact transactional state. A verified archive is the independent
semantic recovery path when no acceptable physical chain exists. Differing
database and archive high-water marks are compared byte-for-byte under ADR
0029; unexplained gaps, overlaps, rollback, or divergence stop recovery.
Archive-ahead state is recovered through the clean archive path rather than
being overlaid on a PITR database. Database-ahead state remains isolated until
the archive relationship is explained and a reviewed continuation is selected.

All listeners, pollers, workers, tunnel processes, and exporters remain off
during recovery. Point-in-time rollback may restore revoked or superseded
credential rows, so request credentials are reissued and provider credentials
are reviewed or rotated before any service activation. No restored credential
row authorizes exposure by itself.

### Verification cadence

Backup age, WAL age/backlog, offsite-copy age, verification failure, and storage
pressure are monitored continuously. An isolated PITR drill runs at least
monthly. A full exercise covering the physical chain, primary signed archive,
encrypted secondary archive bundle, credentials-off posture, and sealed-key
destruction reconciliation runs at least quarterly. Evidence is content-free
and records achieved RPO/RTO rather than assuming the objectives were met.

## Consequences

- Continuous WAL plus daily verified base backups is the only production PITR
  design accepted by this ADR; logical dumps remain supplemental evidence.
- Retention consumes enough space for eight daily and five weekly chains and
  fails safe under uncertainty.
- Recovery requires independently held identities, anchors, configuration, and
  operator choices; one recovery object cannot bootstrap all trust.
- ADR 0028 governs key-provider recovery and ADR 0029 governs archive comparison
  and continuation. A database restore alone never authorizes reactivation.
