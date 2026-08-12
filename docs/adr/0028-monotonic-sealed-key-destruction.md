# ADR 0028: Monotonic sealed-key destruction

- Status: Accepted
- Date: 2026-08-12
- Supersedes: None
- Extends: ADR 0007 and ADR 0017

## Context

ADR 0017 makes a sealed memory unreadable by destroying its external
per-memory DEK. A key-provider backup taken before that destruction can still
contain the DEK. Restoring such a backup without a newer destruction authority
would resurrect data ScaleVault had reported as cryptographically erased.

Deleting every old recovery copy before acknowledging a forget is brittle and
cannot provide immediate, retryable erasure. ScaleVault therefore needs a
destruction authority whose state cannot be rolled back with provider material.

## Decision

### Destruction authority

ScaleVault uses a separately rooted, append-only monotonic destruction ledger.
It is the system of record for completed DEK destruction. Provider control
tombstones, PostgreSQL rows and events, archive records, and backup catalogs are
evidence and workflow state; none may negate a ledger fact.

Each immutable ledger record binds one content-key identifier to its tenant,
lineage, and memory identities, a stable provider destruction receipt, a
version, and an integrity digest. A key has at most one identity and receipt.
Duplicate identical publication is idempotent. A duplicate with different
identity or receipt, an unknown record version, malformed bytes, a missing
required record, or any integrity conflict fails closed.

The ledger lives outside the key-provider material and control roots and is a
separate recovery object. Key-provider backup and restore operations must never
copy over, replace, truncate, or prune it. Ledger backups and exact freshness
anchors are retained under independent operator custody. The routine provider
backup service receives no authority to modify ledger history.

Append-only local files cannot by themselves prove that an entire directory
was rolled back. Every recovery therefore supplies an independently retained
exact ledger anchor, containing at least its version, record count or
generation, and aggregate digest. The recovered ledger must match or extend the
accepted anchor according to an explicitly verified monotonic rule. Missing,
stale, corrupt, conflicting, or rolled-back ledger state, or a missing anchor,
disables key reads, provisioning, recovery completion, and erasure claims. It
must not be treated as an empty ledger.

### Ordering and retry behavior

Hard forget proceeds in this order:

1. The canonical command commits the tombstoned memory and `purge_pending`
   state and durably queues the destruction job.
2. The destruction capability validates the provider identity and durably
   publishes the immutable ledger fact before making key material absent.
3. It durably publishes or confirms the provider control tombstone, unlinks the
   DEK material by its exact identifier, synchronizes the material and control
   directories, and removes stale active control state.
4. The database transaction appends the purge-completed event, records only the
   destruction receipt hash, marks the projection
   `cryptographically_erased`, deletes derived search material, and queues
   archive export.
5. The post-purge archive and secondary archive copy are exported and verified.
   Backup catalogs mark every provider backup that might contain the DEK as
   requiring reconciliation with this ledger generation; such a backup is not
   independently usable key state.
6. A final operator claim covering all retained ScaleVault recovery paths is
   permitted only after the current ledger anchor, database state, archive
   state, secondary copy, and applicable backup catalogs agree.

A crash or retry at any step repeats exact identity checks. Once a ledger fact
exists, provider construction, provisioning, reads, destruction retries, and
every restore must apply it: publish/confirm the matching tombstone, remove any
restored material and active record, and refuse the key. A destroyed key is
never provisioned again. Database rollback to `purge_pending` may repeat the
completion event workflow, but it cannot make the DEK readable.

### Restore and backup rules

Routine key-provider backups may be activated only when all of these are true:

- they are encrypted to an explicit recovery recipient whose private identity
  is held separately;
- their manifests bind the provider generation and required destruction-ledger
  anchor;
- recovery tooling restores provider data into a new inactive location;
- the independently recovered and anchored ledger is validated before the
  provider is constructed or any read is allowed; and
- reconciliation scans every ledger fact and makes destruction win before
  canonical state is examined.

A provider tombstone not represented by the recovered ledger is a conflict,
not proof that the ledger is complete. Recovery stops for investigation. A
ledger fact may safely defeat a stale active provider record even when the
restored database and archive predate the forget.

Provider-backup rotation may remove old encrypted generations only after their
dependencies and holds are known. Ledger history and accepted external anchors
are retained for at least as long as any database, archive, bundle, provider
backup, or other permitted recovery object could refer to the destroyed key.
They are not pruned merely because the newest database says the key is gone.

### State and claims

`purge_pending` means canonical retrieval is ineligible and destruction work
must converge, but ScaleVault has not yet durably completed the DEK destruction
and database event workflow. `cryptographically_erased` means the ledger fact,
provider material removal, and canonical completion event have succeeded. It
does not by itself certify that every recovery copy was inventoried; that
broader claim requires step 6 above.

The accepted claim is limited to envelope-encrypted content and the documented
ScaleVault database, archive, secondary-copy, provider-backup, and destruction-
ledger boundary. It excludes plaintext memories, Genesis compatibility
plaintext, plaintext disclosed before sealing, physical-media sanitization,
and unknown or unauthorized external copies.

## Consequences

- A stale key-provider backup is safe only when combined with a current,
  independently anchored destruction ledger.
- Loss or ambiguity of destruction state sacrifices availability rather than
  allowing a possibly destroyed key to be read.
- The ledger is durable recovery infrastructure with independent custody, not
  an implementation detail inside the provider directory.
- Routine key-provider backup activation and broad erasure claims remain gated
  on recovery and freshness-anchor tests.
