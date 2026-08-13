# Backup and restore

ScaleVault has three independent recovery paths. PostgreSQL physical recovery
is preferred; primary Forgejo history and an encrypted full-history secondary
bundle are semantic recovery paths. A successful backup command is not a
successful recovery proof. Each path requires isolated restoration, invariant
verification, and content-free evidence.

| Recovery source | Contains | Deliberately excludes | Procedure |
|---|---|---|---|
| Encrypted PostgreSQL base backup plus WAL | Canonical database state at a selected recovery point | Runtime files and encryption private identity | [PostgreSQL PITR](runbooks/postgresql-pitr.md) |
| Signed primary Forgejo archive | Deterministic canonical snapshots/events and compatibility metadata | Credentials, keys, embeddings, leases, exporter checkpoints, deployment configuration | [Forgejo recovery](runbooks/forgejo-recovery.md) |
| Encrypted secondary Git bundle | Complete verified signed archive history | Recovery private identity and the same archive exclusions | [Secondary-bundle recovery](runbooks/secondary-bundle-recovery.md) |

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

1. confirm the previous chain and offsite copy are current before starting;
2. create an encrypted physical base backup with manifest and WAL continuity;
3. verify the completed backup independently;
4. verify the already-pushed Forgejo head and its external rollback anchor;
5. create, verify, and encrypt a complete Git bundle, then copy only the
   ciphertext to the independent failure domain;
6. run the retention validator without deleting anything; destructive pruning
   remains blocked until authenticated PITR/dependency/hold authority exists;
   and
7. record only bounded result codes, safe identifiers, timestamps, counts, and
   digests.

A stale backup age, failed `archive_command`, missing WAL, failed bundle
verification, offsite-copy failure, or divergence blocks pruning and raises an
operator alert. Use [WAL failure](runbooks/wal-failure.md) and
[Archive divergence](runbooks/archive-divergence.md) instead of retry loops that
could destroy evidence.

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
