# Backup and restore

ScaleVault has a preferred PostgreSQL physical recovery path plus two
provider-independent semantic recovery gates: local signed history and an
encrypted full-history bundle. A successful backup command is not a successful
recovery proof. Each accepted path requires isolated restoration, invariant
verification, and content-free evidence. Forgejo provider recovery, remote
promotion, archive continuation, and exporter reactivation are excluded from
Milestone 10 and remain unverified.

| Recovery source | Contains | Deliberately excludes | Procedure |
|---|---|---|---|
| Encrypted PostgreSQL base backup plus WAL | Canonical database state at a selected recovery point | Runtime files and encryption private identity | [PostgreSQL PITR](runbooks/postgresql-pitr.md) |
| Verified local signed archive | Deterministic canonical snapshots/events and compatibility metadata | Credentials, keys, embeddings, leases, exporter checkpoints, deployment configuration | Local signed-history verification followed by clean disposable-database restore |
| Encrypted secondary Git bundle | Complete verified signed archive history | Recovery private identity and the same archive exclusions | [Secondary-bundle recovery](runbooks/secondary-bundle-recovery.md) |

The [Forgejo recovery runbook](runbooks/forgejo-recovery.md) is retained as
future, separately authorized guidance. It is not an M10 recovery path or
acceptance gate.

## Installed storage topology

The routine Memory Node has one NFS mount, `/mnt/memory`. Canonical PostgreSQL
`PGDATA` remains `/mnt/memory/kivra-memory/postgresql/17/main`; encrypted base,
WAL, timeline-history, manifest, index, and completion objects are published to
`/mnt/memory/kivra-memory/backups/postgresql-pitr`. Both trees share the same
NAS, dataset, mount availability, and capacity pool. Their directory and
ownership separation limits write scope but is not an independent recovery
copy or failure domain.

Plaintext backup staging uses local scratch at
`/var/lib/kivra-memory/backup-staging`. The isolated recovery host materializes
decrypted drills only below `/var/lib/kivra-memory/recovery`. Neither local path
is a durable backup, and the recovery private identity remains off the routine
Memory Node. See
[ADR 0036](adr/0036-single-nfs-recovery-store-and-local-scratch.md).

## Recovery invariants

1. Never restore over an active canonical database, active production data
   directory, or the exporter worktree.
2. Disable API, ingress, tunnel, workers, pollers, and exporter on the recovery
   node before materializing recovery data.
3. Supply backup decryption identity, sealed-content keys, the independent
   destruction ledger, credentials, signer trust, host-key trust, and rollback
   anchors independently of the object they protect.
4. Verify the selected source before restore and verify canonical invariants
   again afterward. Missing, stale, corrupt, unsigned, divergent, or
   incompatible input fails closed.
5. A database rollback can restore credential rows or an older destruction
   view. Preserve the current root-owned destruction ledger at
   `/var/lib/kivra-memory-sealed/destruction-ledger`, construct the recovered
   provider with that ledger, and reconcile stale keys before any listener or
   writer starts. The ledger is explicitly excluded from content-key backups
   and must match or monotonically extend its independently retained exact
   freshness anchor; absence or ambiguity disables sealed operations.
6. Rebuild projections and embeddings through supported application paths.
   Never copy stale worker leases or exporter checkpoint state into a recovered
   installation.
7. Preserve divergence for investigation. Never amend, merge, force-push, or
   rewrite recovery history.
8. Archive verification pins the exact external head, final manifest digest,
   event high-water mark, signer epochs and public-key fingerprints. Every
   epoch transition requires its canonical record plus both old- and new-key
   detached signatures. A compromised signer is accepted only through its
   independently anchored exact last commit/sequence cutoff.

## Routine backup cycle

Follow [Backup operations](runbooks/backup-operations.md). The operator must:

1. confirm the previous local chain is current and sufficient no-prune capacity
   remains in the one pool shared by canonical `PGDATA` and the encrypted chain
   before starting;
2. create an encrypted physical base backup with manifest and WAL continuity;
3. verify the completed backup independently;
4. verify the exact local signed-history head and its external rollback anchor;
5. create, verify, and encrypt a complete Git bundle from that exact local
   history; transfer to Backblaze or another offsite destination remains an
   operator-managed operation outside M10;
6. run the retention validator without deleting anything; any future pruning
   requires a new accepted architecture decision and authenticated dependency/
   hold authority;
   and
7. record only bounded result codes, safe identifiers, timestamps, counts, and
   digests.

A stale backup age, failed `archive_command`, missing WAL, failed bundle
verification, or divergence fails the local gate and raises an operator alert.
There is no destructive pruning authority in M10 regardless of health or
capacity. Use [WAL failure](runbooks/wal-failure.md) instead of retry loops that
could destroy evidence. PBS protection and Backblaze transfer, retention,
freshness, retrieval, and deletion are operator-managed and outside this
procedure.

Nightly NAS backups, PBS protection, and Backblaze transfer are operator-managed
outside this topology. In the absence of separate operator evidence, no
acceptance result may claim that any such copy exists, is fresh, is independent
of the NAS dataset, or has been restored successfully.

## Recovery activation gate

No recovered installation is activated until all applicable gates pass:

- selected release and exact migration compatibility are established;
- PostgreSQL system identifier, timeline, target, extensions, event hashes,
  high-water marks, projections, and aggregate digests are valid;
- archive head, external anchor, first-parent history, signatures, manifests,
  signer transitions/compromise cutoffs, schemas, hashes, and bounds are valid;
- destroyed sealed-content keys remain destroyed across every permitted key
  backup and recovery source; the independent current destruction ledger is
  present and reconciliation removed or rejected every stale restored key;
- credentials are reviewed and reissued where rollback or compromise is
  possible;
- embeddings and derived projections are rebuilt and synthetic retrieval
  canaries pass;
- writers remained disabled during proof, temporary plaintext is removed, and
  cleanup is independently checked.

The acceptance result may describe successful recovery only within the tested
database, archive, secondary-copy, and key-backup boundary. It must not claim
physical-media erasure or absence of unknown third-party copies.
