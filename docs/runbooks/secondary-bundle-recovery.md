# Encrypted secondary-bundle recovery

This is the provider-independent encrypted-bundle gate used by M10. Backblaze
retrieval is operator-managed and not required: the selected ciphertext may be
supplied from the local accepted artifact set. No Forgejo provider, remote, or
continuation operation is performed.

1. Obtain the selected ciphertext and content-free sidecar. Verify object
   identity, age, size bounds, and ciphertext digest before decryption.
2. Prepare protected temporary storage on the isolated recovery host. Disable
   swap/core dumps for the recovery process as required by installation policy.
3. Supply a mode-`0600` recovery private identity file separately. Never copy
   it into the ciphertext directory, evidence record, environment dump, or
   command line.
4. Materialize the bundle into a new output repository:

   ```bash
   kivra-memory-archive-recovery --config /absolute/recovery.json \
     bundle-materialize --encrypted-bundle /absolute/local-bundle/object.age \
     --expected-ciphertext-sha256 <EXTERNALLY_RETAINED_SHA256> \
     --identity-file /absolute/protected/identity \
     --output-repository /absolute/new-recovery-repository \
     --scratch-directory /absolute/protected-scratch
   ```

   The command checks the independently retained ciphertext digest before
   decryption, then verifies authenticated decryption, plaintext bundle
   integrity, refs/head, complete objects, and the configured signed history
   before returning fixed content-free JSON. The output repository must not
   exist beforehand.
5. Treat the new output repository as the local recovery source and verify its
   complete first-parent history, signer epochs and applicable transitions or
   compromise cutoffs, signatures, manifest chain, schemas, hashes, bounds,
   compatibility, and independently supplied external anchor.
6. Restore into a freshly migrated empty database. Require the exact same head,
   final manifest, event high-water mark, signer policy, and object bytes as the
   accepted local signed-history proof. Rebuild projections and embeddings,
   reconcile any permitted key backup against the current independent
   destruction ledger, and run content-free canary gates.
7. Stop recovery services, remove the decrypted bundle, clone, database,
   recovery identity staging, and temporary configuration according to
   [Drill cleanup](drill-cleanup.md). Confirm no plaintext scratch remains.

Wrong key, authentication failure, partial ciphertext, stale or unexpected
head, extra ref, incomplete bundle, same-anchor mismatch, or cleanup failure is
a failed drill. Do not fall through to an older object without recording and
investigating the failure. This drill makes no remote equality, offsite
placement, provider restore, archive continuation, or exporter-reactivation
claim.
