# Primary Forgejo recovery

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
5. Prepare an absolute recovery configuration that pins the local clone, exact
   branch/head, application/Alembic versions, and gap-free signer epochs whose
   public allowed-signers files are supplied separately. Verify it:

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
9. Archive recovery never re-anchors an existing target. Require the fixed
   `new_immutable_archive_target_required` result and exercise continuation only
   against a newly provisioned isolated immutable target. Never point the
   exporter at the production remote as part of a drill.

Stop and follow [Archive divergence](archive-divergence.md) on any head,
signature, manifest, signer, host-key, or prefix discrepancy. Finish with the
[cleanup procedure](drill-cleanup.md).
