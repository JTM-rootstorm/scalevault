# ADR 0034: Local signed-archive Milestone 10 acceptance

- Status: Accepted
- Date: 2026-08-13
- Supersedes: None
- Amends: ADR 0028, ADR 0029, ADR 0030, and ADR 0033

## Context

ADR 0029 defines provider-backed archive recovery and continuation through a
private Forgejo target. ADR 0030 defines the associated credential lifecycle,
and ADR 0033 separates operator-managed offsite custody from ScaleVault's local
recovery-object correctness. Those decisions remain useful for a future
Forgejo activation, but exercising the provider path is not necessary to prove
the provider-independent signed-history and encrypted-bundle formats.

Milestone 10 is being accepted for a private, single-owner installation whose
archive exporter is disabled. Requiring a temporary Forgejo deployment merely
to close the milestone would create provider credentials and operational state
that the accepted installation does not use. The narrower boundary must not be
reported as evidence that Forgejo recovery or archive continuation works.

The milestone's hard-forget drill also needs an exact boundary. With archive
export disabled, an archive completion event cannot be used as a prerequisite
for the installed PostgreSQL and key-provider erasure claim.

## Decision

### Milestone 10 provider exclusion

Forgejo-specific recovery, archive continuation, provider credentials,
provider evidence, checkpoint reconstruction, target promotion, and exporter
reactivation are excluded from Milestone 10. The milestone performs no live
Forgejo clone, fetch, push, restore, target creation, re-anchoring, deploy-key
or host-key exercise, provider API operation, or production archive-exporter
activation.

Acceptance records the Forgejo provider path as `excluded / not evaluated`,
never passed. Milestone 10 makes no claim that:

- a Forgejo instance or remote was restored;
- a remote contains the accepted history or equals a local recovery source;
- a target was promoted or an exporter checkpoint was reconstructed;
- an exporter resumed or appended a production commit; or
- Forgejo credentials or host keys were validated.

This is a milestone-scoped amendment. It does not discard existing signed
history, change the single-writer archive contract, or supersede ADR 0029's
rules for a future Forgejo recovery and continuation exercise. Existing-target
re-anchoring remains unsupported for Milestone 10 and exceptional under ADR
0029 outside this acceptance boundary.

### Provider-independent archive gate

Milestone 10 still verifies archive correctness locally. The accepted gate
requires:

- an externally anchored exact head, final manifest digest, event high-water
  sequence, compatible release and migration binding, signer fingerprints,
  and signer policy;
- bounded enumeration and verification of the complete first-parent history
  through that head, including exact objects, tree layout, manifests, event
  ranges, hashes, parents, and commit signatures;
- a clean local restore rather than an overlay of active or existing state;
  and
- decryption and verification of the full-history `age`-encrypted Git bundle
  using an independently supplied recovery identity.

When the accepted signer policy contains a planned transition, the gate also
requires its exact dual-signed transition record. When it contains a
compromise declaration, the gate requires the independently anchored exact
commit and event-sequence cutoff. Neither proof is invented when the accepted
policy contains no such condition.

A local test-only Git appender or direct `update-ref` operation may create
fixtures, but it is not production continuation evidence. Local verification
does not establish an installed archive cadence, remote equality, target
promotion, checkpoint reconstruction, or resumed-exporter behavior.

### Encrypted-bundle semantic restore

Encrypted-bundle recovery is accepted only when the materialized history is
proved semantically recoverable. A future gate may compose two independently
valid proofs only when they are bound to the exact same head, final manifest,
event high-water sequence, signer policy, and object bytes. Milestone 10 uses
the simpler direct path: decrypt and verify the bundle, materialize its exact
history, and restore it into a freshly migrated disposable database through
the production archive recovery path.

The restore environment is clean and isolated. It receives no archive signing
private key, deploy credential, provider credential, bearer secret, content
key, database credential, or authority to activate an exporter. The resulting
database and materialized history are disposable evidence, not a promoted
production target.

### Hard-forget boundary

The Milestone 10 hard-forget claim covers only:

- canonical PostgreSQL state;
- the local key-provider state;
- the separately rooted destruction ledger and its independently retained
  accepted freshness anchor; and
- the installed PostgreSQL PITR recovery boundary.

Recovery must reconcile any restored key-provider material against the
accepted destruction ledger so that a stale key cannot resurrect forgotten
content. Local signed-archive history and encrypted archive bundles remain
separate format and recovery gates while archive export is disabled. They are
excluded from the Milestone 10 erasure-dominance claim, so no post-purge
archive completion event, archive continuation, or exporter activation is
required or claimed.

This boundary does not broaden an erasure claim to unknown third-party copies,
operator-managed offsite copies, or physical media. ADR 0033 continues to
govern the no-claim boundary for Backblaze; this amendment introduces no
provider integration or offsite-copy claim.

## Consequences

- Milestone 10 can accept provider-independent signed-history and encrypted-
  bundle recovery without deploying or mutating Forgejo.
- Forgejo recovery, credentials, promotion, continuation, and exporter append
  remain unverified and available for a later explicitly authorized exercise.
- Existing archive history and ADR 0029's trust and continuation rules are
  preserved rather than replaced by local test operations.
- The installed hard-forget result is exact about the recovery paths it covers
  and does not depend on an inactive archive exporter.
- Backblaze transfer and external alert delivery remain operator-managed and
  outside the Milestone 10 acceptance claim under ADR 0033.
