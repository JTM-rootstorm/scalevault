# ADR 0029: Archive recovery continuation and signer epochs

- Status: Accepted
- Date: 2026-08-12
- Supersedes: None
- Extends: ADR 0003 and ADR 0015
- Amended by: ADR 0033 and ADR 0034

## Context

ADR 0015 defines a deterministic signed single-writer archive and a clean
database restore seam. It does not yet define production Git traversal,
PostgreSQL-versus-archive recovery precedence, exporter continuation after an
archive-only restore, or signing-key transition and compromise rules. The
archive intentionally excludes exporter checkpoints and private keys.

Restoring valid semantic state is not permission to invent an exporter
checkpoint or rewrite a published branch. Likewise, retaining an old signer
forever would allow a compromised key to authorize new history, while simply
removing it would destroy historical recovery.

## Decision

### Verification-only recovery boundary

Archive recovery uses a verification-only configuration that contains public
trust and exact constraints but can never resolve, read, or invoke the archive
signing private key. It is separate from exporter configuration and contains:

- the exact archive target and branch;
- a pinned Forgejo host key and a read-only recovery identity;
- an externally held exact accepted head commit;
- the expected final manifest SHA-256 and source high-water sequence;
- an explicit signer-epoch map and applicable transition records;
- any compromised-signer cutoffs; and
- an exact head-to-compatible-application-release and Alembic-revision binding.

The head, manifest, high-water, compatibility, and signer bindings are retained
outside the archive under root-controlled operator custody. Until a later
reviewed archive format records compatible release metadata, the external
binding is mandatory and is not inferred from code found in the archive.
Missing or ambiguous bindings fail closed.

The production reader enumerates every commit from genesis to the pinned head
over the first-parent chain. It rejects merges and reads exact commit, tree, and
blob objects through fixed Git arguments without checking out attacker-chosen
paths. It enforces per-object, commit-count, and aggregate byte limits and
verifies every signature, signer epoch, parent, exact tree layout, manifest
chain, schema, file digest, event range, snapshot boundary, and high-water
value before opening a database transaction. A remote behind, ahead of, or
divergent from the external head is preserved for investigation; recovery does
not fetch an unanchored replacement or repair the remote.

### Database and archive comparison

A PITR database and an archive are comparable only by their canonical event
prefix: exact sequence, event identity, canonical bytes and hashes, aggregate
identity, and manifest/checkpoint relationship. Matching counts alone are not
proof.

If the database and archive agree at the selected high-water point, recovery
may use the database and rebuild derived state. If the verified archive is
ahead, ScaleVault performs a clean archive-only restore into a freshly migrated
empty database; it does not append Git-ahead events over the PITR database. If
the database is ahead, both remain isolated until the missing archive suffix is
explained and the continuation procedure is authorized. Any mismatch within a
claimed common prefix is divergence and stops recovery.

### Continuation after archive-only restore

The default continuation creates a new immutable archive target. The operator
copies the exact fully verified history through the externally anchored head to
a new empty target without changing any commit, tree, signature, or branch
topology. The recovered exporter may reconstruct operational checkpoint state
only from that exact verified head, final manifest, and high-water binding.
After it verifies that the new remote contains precisely that history, it may
append one new first-parent commit through the normal single writer. It may
never regenerate genesis, duplicate events, amend, merge, force-push, or treat
a newly authored equivalent tree as the old history.

Re-anchoring the existing archive target is exceptional and disabled by
default. It requires a separate, recorded operator authorization for that
target and recovery event, plus exact externally anchored proof of:

- the remote head commit and complete first-parent prefix;
- final manifest digest and event high-water sequence;
- equality with the database restored from that prefix;
- the compatible application and migration revisions; and
- absence of any remote-ahead, rewritten, or divergent object.

Only then may the exporter reconstruct its checkpoint to the existing exact
head and perform a normal append. Failure preserves both sides and stops. No
generic `--force`, divergence-healing, or best-effort checkpoint option exists.

### Signer epochs and transition evidence

Verification configuration contains an explicit ordered epoch map. Each epoch
binds an epoch identifier, allowed signer principal, exact public key, first
accepted event sequence, optional last accepted event sequence, and transition
record identity. Each commit is valid only under the one epoch covering its
manifest event range. Overlap, gaps, an unknown signer, or a commit spanning an
epoch boundary fails closed.

A planned transition uses an external canonical transition record rather than
changing the archive-v1 schema. The record binds the archive target, previous
and next epoch identifiers and public-key fingerprints, the exact last accepted
old head and event sequence, the exact first sequence for the new epoch, and a
transition identifier. Detached signatures from both the old and new signing
keys cover the exact record. The record and epoch map are root-controlled
verification inputs retained with the external archive anchors. Rotation is
not complete until a verifier with no private signing material accepts the old
history, transition, and first new-epoch commit.

If a signer is compromised, configuration records an explicit last accepted
commit and event-sequence cutoff anchored independently of that signer. History
at or before the cutoff remains recoverable only when its exact commits match
the pre-compromise anchor; later commits from that signer are rejected. An
emergency successor epoch is authorized through an independently controlled
trust update, not by a transition signed only with the compromised key. The
incident never silently widens an epoch or accepts a new key learned from
archive content.

Signing-key rotation is independent of Forgejo deploy-key and read-only
recovery-key rotation. Transport credentials do not sign history, and signing
keys receive no repository administration authority. Forgejo host-key change
requires an explicit pin update after independent verification; mismatch never
falls back to trust-on-first-use.

### Encrypted secondary copy

The secondary archive copy is a complete Git bundle created only from an
already-pushed head that has passed the verification above. The pipeline runs
`git bundle verify`, encrypts the full-history bundle with `age` to the
operator-provided recovery recipient, atomically publishes it into a separate
failure domain, and retains content-free source-head, manifest, ciphertext
digest, size, time, destination class, and result metadata. The plaintext
bundle digest remains only in protected in-memory verification flow and is not
emitted by the CLI or retained in status. Plaintext scratch is removed only
after the encrypted copy verifies.

A bundle is produced from each newly accepted pushed archive head. Updates may
be safely coalesced while one bundle is in progress, but the next run must use
the newest externally accepted head. A changed accepted head without a verified
encrypted secondary copy for more than one hour alerts. At least monthly, the
operator materializes, decrypts, verifies, and restores a bundle through the
production archive recovery path in an isolated environment.

The bundle contains no signing or deploy private key, allowed-signers private
material, DEK or provider backup, bearer pepper, digest-binding secret,
database/provider credential, or deployment configuration. Acceptance decrypts
with independently supplied recovery material, re-verifies exact signed
history, and restores a disposable database; bundle integrity alone is not
semantic recovery proof.

## Consequences

- Historical signatures remain useful across planned rotation without trusting
  an old signer for future commits.
- Signer transitions add external trust artifacts now; changing the archive
  schema requires a later coordinated ADR and migration.
- Archive-ahead recovery favors a clean restore over an in-place hybrid.
- A new immutable target is the normal continuation path. Existing-target
  re-anchor remains a narrowly authorized recovery operation with exact proof.
- The secondary copy preserves one logical writer because it replicates
  verified history and never authors semantic commits.
