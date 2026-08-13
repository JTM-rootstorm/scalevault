# Future Forgejo recovery (not an M10 procedure)

Forgejo provider restore, clone/fetch, credentials, host-key exercise, target
promotion, archive checkpoint reconstruction, continuation, and exporter
reactivation are excluded from Milestone 10 and remain unverified. Do not run
this procedure or use source/tests as evidence for any of those claims during
M10 closeout. This runbook is retained only as future guidance and requires a
separate operator authorization and acceptance plan.

Use this path only when the signed archive is selected as the semantic recovery
source. It does not restore credentials, keys, embeddings, worker leases,
exporter checkpoints, or deployment configuration.

1. Prepare a freshly migrated, empty, disposable PostgreSQL database with all
   writers/listeners disabled.
2. Clone/fetch the exact protected branch with the dedicated read-only recovery
   identity and pinned Forgejo host key. Never use the exporter deploy key or
   `accept-new`.
3. Verify the observed head against the external rollback anchor, then verify
   the complete first-parent history, signer epochs/transitions, signatures,
   manifests, schemas, hashes, object bounds, and snapshot/event boundary.
4. Resolve the exact compatible application and Alembic revision from archive
   metadata. Stop rather than guessing or running an incompatible decoder.
5. Prepare an absolute recovery configuration that pins the archive target,
   local clone, exact branch/head, final manifest digest, high-water sequence,
   application/Alembic versions, and gap-free signer epochs. Each epoch binds
   its ID, exact public key fingerprint, allowed-signers file/principal, bounded
   event range, and transition-record ID. Every planned transition supplies the
   canonical record plus old/new detached signatures; a compromised epoch also
   supplies its independently anchored last accepted commit and event sequence.
   Verify it:

   ```bash
   kivra-memory-archive-recovery --config /absolute/recovery.json verify
   ```

6. Run the production restore against a database whose name begins
   `scalevault_recovery_`, using the dedicated recovery role and a mode-`0600`
   database URL file referenced by the protected configuration:

   ```bash
   kivra-memory-archive-recovery --config /absolute/recovery.json \
     restore-database --confirmation restore-into-disposable-empty-database
   ```

   The preflight requires the exact migration revision, an empty set of
   application tables, and the recovery role needed to restore through forced
   RLS. It must reject any non-disposable or populated destination.
7. Rebuild semantic projections and embeddings, then verify event continuity,
   aggregates, high-water marks, and content-free retrieval canaries.
8. Prove archive-excluded credentials, keys, leases, checkpoints, and
   deployment configuration were not synthesized. Reissue independently before
   any later activation. Preserve and apply the current independent destruction
   ledger before restoring or reconciling a permitted key backup.
9. Future archive continuation never re-anchors an existing target. A future
   authorized drill may pre-create an empty
   local bare target with no refs, objects, or alternates, then run:

   ```bash
   kivra-memory-archive-recovery --config /absolute/recovery.json \
     continue-new-target \
     --confirmation continue-to-new-immutable-target \
     --target-repository /absolute/new-empty-bare-target \
     --target-id <UUIDV7_TARGET_ID> \
     --checkpoint-id <UUIDV7_CHECKPOINT_ID> \
     --target-name <BOUNDED_TARGET_NAME> \
     --repository-reference <FILE_URI_OF_TARGET_REPOSITORY> \
     --target-branch <ANCHORED_SOURCE_BRANCH>
   ```

   The protected configuration must reference its mode-`0600` local-only
   database URL file and the same disposable `scalevault_recovery_...` database.
   The repository reference is exactly the canonical `file://` URI of the
   resolved target repository. A typo, symlink, SSH URL, or mismatch rejects
   before copying. The command copies only the externally anchored objects,
   reverifies signatures and byte equality, checks database migration/counter/
   event equality, records a disabled target, and records one committed
   checkpoint with no remote commit SHA through existing locked handlers. It
   never signs, appends, pushes, promotes the local target to a remote, or
   activates an exporter. Require
   `continuation=verified_remote_promotion_required`.

10. A checked-in production SSH-promotion command does not yet exist. Keep the
    reconstructed target disabled until a separately reviewed procedure pins
    SSH identity/host trust, promotes byte-identical history to a new immutable
    remote, and proves its exact head. Only then configure and activate the
    normal single exporter and prove its first operation is exactly one normal
    first-parent append. Never point it at the old or production target during
    a drill.

Stop and follow [Archive divergence](archive-divergence.md) on any head,
signature, manifest, signer, host-key, or prefix discrepancy. Finish with the
[cleanup procedure](drill-cleanup.md).
