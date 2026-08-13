# Backup-aware hard-forget recovery drill

This runbook exercises one synthetic envelope-encrypted record across the
canonical PostgreSQL hard-forget path, the local key provider, the independent
destruction ledger and anchor, a pre-forget provider backup, and the selected
installed PITR chain. It does not prove erasure from signed archives, bundles,
unknown copies, plaintext imports, physical media, the NAS, or Backblaze.

The routine provider-backup facility may remain disabled. In that case, mark
only the backup-specific branch not applicable; the requester, broker, anchor,
hard-forget, and restore-reconcile gates still apply. Never enable or inspect a
live provider backup merely to run this drill.

## Authorization and stop conditions

Record approval for the exact synthetic tenant/scope, content-key identity,
request root, provider control/material roots, separate ledger and anchor,
Phase 2 provider copy, installed base/WAL identifiers and target, protected
manifest, and disposable restore roots. Confirm that the target is synthetic.

Stop before mutation on any identity mismatch, non-synthetic target, anchor
mismatch, unexpected file in the provider copy, provider copy containing the
ledger or anchor, broker capability drift, missing Phase 2 binding, or cleanup
ambiguity. The drill does not authorize broad deletion, backup pruning, live
provider activation, or alteration of an accepted recovery object.

## Phase 2 binding

1. Create the synthetic sealed record through the canonical handler before the
   accepted base backup. Keep plaintext and key material out of evidence.
2. Copy only that record's local provider `control` and `material` state into a
   bounded drill-owned root. Do not include the destruction ledger or either
   anchor copy.
3. Compute the domain-separated synthetic correlation digest from the exact
   database ciphertext, provider key reference, and drill generation. Compute
   separate SHA-256 digests for the selected base backup, WAL/recovery window,
   and recovery target using the protected recovery procedure.
4. Create the protected manifest without printing the private inputs:

   ```console
   python -m kivra_memory.security.hard_forget_drill create \
     --provider-root /protected/drill/provider-backup/keys \
     --base-backup-sha256 "$BASE_BACKUP_SHA256" \
     --wal-window-sha256 "$WAL_WINDOW_SHA256" \
     --recovery-target-sha256 "$RECOVERY_TARGET_SHA256" \
     --synthetic-correlation-sha256 "$CORRELATION_SHA256" \
     --output /protected/drill/hard-forget-manifest.json
   ```

The helper accepts exactly one canonical active control record and matching
32-byte material file. Its manifest and stdout contain only fixed labels,
counts, byte counts, and SHA-256 digests. It fails closed on additional files,
links, special files, mismatched identities, destroyed controls, or malformed
records. It does not create, copy, restore, activate, or delete provider state.

Protect the manifest as drill evidence. Record its SHA-256, the provider
inventory aggregate, both counts, and byte count. Do not record filenames,
UUIDs, provider references, ciphertext, receipts, or key material.

## Phase 5 destruction and anchor acknowledgement

1. Submit hard forget through the installed mutation path. Confirm PostgreSQL
   reports `purge_pending` and the real outbox contains the bounded purge job.
2. Let the unprivileged requester publish its immutable request. Completion
   must fail while no authoritative destruction fact exists.
3. Run the dedicated destruction broker. Confirm it publishes the exact ledger
   fact and a new local anchor, removes active provider control/material, and
   leaves the database operation pending.
4. Independently verify and retain the new anchor, then install that exact
   value as the accepted credential. Restart only the named consumers that
   receive it.
5. Retry the outbox job with the restarted requester. Confirm the tombstone is
   present, active control/material and derived embeddings are absent, and only
   then PostgreSQL records `cryptographically_erased`.

An old or unaccepted anchor must fail closed even when the provider tombstone
and ledger fact exist. Do not treat broker execution alone as acknowledgement
or erasure completion.

## Stale-copy and PITR non-resurrection

Before copying the stale provider backup into its disposable restore root,
verify exact Phase 2/5 correlation:

```console
python -m kivra_memory.security.hard_forget_drill verify \
  --provider-root /protected/drill/provider-backup/keys \
  --base-backup-sha256 "$BASE_BACKUP_SHA256" \
  --wal-window-sha256 "$WAL_WINDOW_SHA256" \
  --recovery-target-sha256 "$RECOVERY_TARGET_SHA256" \
  --synthetic-correlation-sha256 "$CORRELATION_SHA256" \
  --manifest /protected/drill/hard-forget-manifest.json
```

The manifest digest, inventory counts, byte count, inventory aggregate, Phase 2
base, WAL-window, recovery-target, and synthetic-correlation digests must match
exactly. A mismatch stops the drill; do not repair, reinterpret, or replace a
fixture in place.

1. Copy the verified provider backup to a fresh isolated provider root. Retain
   the current independent ledger and accepted anchor; never overlay either
   with restored state.
2. Run `kivra-memory-sealed-restore-reconcile` before starting any API, ingress,
   worker, or reader. Confirm stale active control and material are absent, the
   exact tombstone is present, and key reads fail.
3. Restore a fresh isolated PostgreSQL instance from the base/WAL chain and
   target named by the protected binding. Recompute the database-side
   correlation from its ciphertext and provider reference, and require exact
   equality with the manifest value.
4. Attach only the reconciled provider root plus the current ledger and
   accepted anchor. Confirm the pre-forget ciphertext remains unreadable before
   any application service is permitted to start.

## Cleanup and evidence

Stop the disposable database and remove only explicitly inventoried,
drill-owned provider copies, decrypted recovery roots, scratch configuration,
sockets, and temporary credentials. Preserve the authoritative destruction
fact and independently accepted anchor. A second operator check must find no
readable synthetic key material or application process attached to a recovery
root.

The content-free evidence record contains pass/fail status, immutable release
checksum, manifest SHA-256, bounded provider counts/bytes/digest, recovery and
correlation digests, old-anchor rejection, current-anchor acknowledgement,
reconcile result, unreadability result, cleanup result, and timestamps. It must
not contain memory content, identifiers, paths, authorization values,
credentials, endpoints, ciphertext, provider references, or receipts.
