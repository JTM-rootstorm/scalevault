# ADR 0035: No-prune recovery retention

- Status: Accepted
- Date: 2026-08-13
- Supersedes: None
- Amends: ADR 0027

## Context

ADR 0027 defines protected PostgreSQL recovery chains and minimum retention of
eight verified daily and five verified weekly generations. Safe automatic
deletion would require authenticated, fresh, replay-resistant evidence of the
complete dependency graph among bases, WAL and timeline history, restore
points, holds, and other recovery consumers.

Milestone 10 has no accepted producer or independently held verification root
for that deletion evidence. Inferring dependencies from local inventory or
using elapsed time alone would allow a stale, incomplete, or tampered view to
authorize destruction. `age` authenticates ciphertext integrity to a recipient;
it does not identify an authorized producer of recovery-retention evidence.

The installed system is backed up and capacity-managed outside ScaleVault, but
those operator arrangements do not grant this helper authority to delete
recovery objects. Milestone 10 therefore needs an intentionally simple
retention posture rather than a speculative recovery catalog or signer.

## Decision

### Zero deletion authority

The Milestone 10 retention helper has zero deletion authority. It retains every
base backup, WAL segment, timeline-history object, declared restore point,
authenticated manifest and index, and explicit hold represented by the
validated installed inventory. It does not unlink, overwrite, compact, expire,
quarantine-as-deletion, or otherwise make a recovery object unavailable.

The eight daily and five weekly generations from ADR 0027 are accumulation and
inventory floors. They are neither deletion authorization nor an elapsed-time
acceptance delay. A candidate may satisfy this gate as soon as the installed
inventory is valid and the no-prune result is proved; it need not wait eight
days or five weeks merely to accumulate distinct labels.

The exact successful retention status is:

`no_prune_dependency_watermark_absent`

This status means the helper validated the inventory and deliberately deleted
nothing because no accepted authenticated dependency watermark exists. It is
not evidence that pruning occurred, that every object is safely deletable, or
that an inferred dependency graph is authoritative.

### Inventory and capacity behavior

Installed inventory validation and capacity alerts are mandatory. A missing
inventory fails closed. Enumeration also fails closed on malformed names or
metadata, missing referenced objects, duplicate conflicts, corrupt or
unauthenticated recovery metadata, ambiguous relationships, incomplete
traversal, or unreadable storage. Such failures do not produce the successful
no-prune status.

Capacity pressure, age, generation count, operator backup schedules, or the
presence of a newer verified base never authorizes deletion. The helper emits
bounded, content-free capacity and inventory status so the operator can add
storage or investigate. Manual pruning and deletion based on an inferred
dependency graph are forbidden under this ADR.

### Requirements for any future pruning design

Any later automatic or manual deletion support requires a new accepted ADR.
That decision must define at least:

- the authoritative dependency-evidence producer;
- an independently held verification root;
- a canonical signed schema for dependencies and deletion candidates;
- freshness, expiry, ordering, and replay rules;
- key custody, rotation, and compromise handling;
- the complete dependency graph across bases, WAL, timeline history, restore
  points, holds, and every supported recovery consumer; and
- the exact authorization and fail-closed procedure for each deletion.

The future design must prove that deleting an object preserves every retained
recovery promise. Local presence, authenticated encryption, or an operator's
unrecorded inference is not a substitute for that evidence.

## Consequences

- Milestone 10 retention is an inventory-and-alert gate with no destructive
  behavior.
- Storage use grows until an operator adds capacity or a later ADR authorizes
  deletion from sufficient evidence.
- Ambiguous, incomplete, malformed, or corrupt inventory sacrifices retention
  automation rather than recoverability.
- The daily and weekly counts remain minimum recovery expectations without
  becoming unsafe pruning rules.
- No recovery catalog, deletion signer, or Backblaze integration is introduced
  for this milestone.
