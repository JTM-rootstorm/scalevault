# Encrypted secondary-bundle recovery

1. Retrieve the selected ciphertext and content-free sidecar from the
   independent failure domain. Verify object identity, age, size bounds, and
   ciphertext digest before decryption.
2. Prepare protected temporary storage on the isolated recovery host. Disable
   swap/core dumps for the recovery process as required by installation policy.
3. Supply a mode-`0600` recovery private identity file separately. Never copy
   it into the ciphertext directory, evidence record, environment dump, or
   command line.
4. Materialize the bundle into a new output repository:

   ```bash
   kivra-memory-archive-recovery --config /absolute/recovery.json \
     bundle-materialize --encrypted-bundle /absolute/offsite/object.age \
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
5. Treat the new output repository as the local recovery source and apply every
   signed-history, signer-transition, manifest, schema, hash, bound,
   compatibility, and external-anchor check used for
   [Forgejo recovery](forgejo-recovery.md).
6. Restore into a freshly migrated empty database, rebuild projections and
   embeddings, reconcile any permitted key backup against the current
   independent destruction ledger, and run content-free canary gates.
7. Stop recovery services, remove the decrypted bundle, clone, database,
   recovery identity staging, and temporary configuration according to
   [Drill cleanup](drill-cleanup.md). Confirm no plaintext scratch remains.

Wrong key, authentication failure, partial ciphertext, stale or unexpected
head, extra ref, incomplete bundle, or cleanup failure is a failed drill. Do
not fall through to an older object without recording and investigating the
failure.
