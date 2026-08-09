# ADR 0016: GitHub ingress v2 runtime and sensitive-path boundary

- Status: Accepted
- Date: 2026-08-09
- Supersedes: None
- Extends: ADR 0004, ADR 0010, ADR 0011, and ADR 0013

## Context

The checked-in ChatGPT proposal-v1 schema is sufficient to preserve the frozen
Genesis source, but it does not identify a canonical persona, branch, or
subject, carries no numeric policy inputs or sensitivity declaration, permits
generic UUIDs that cannot be used by the opaque UUIDv7 status tool, and names
legacy observe/remember operations. Inferring those missing facts would turn
GitHub transport metadata or prose into canonical authority.

The ingress table also requires an idempotency key and payload hash at initial
discovery. A malformed or oversized object may have neither, so it cannot be
registered and quarantined without inventing provenance.

## Decision

### Live proposal contract

`chatgpt-memory-proposal-v1` remains accepted only by explicitly frozen legacy
import workflows. The first live polling contract is
`chatgpt-memory-proposal-v2`. It uses a UUIDv7 `proposal_id`, and that exact
value is the canonical `ingress_id` used by `memory_ingress_status`.

V2 is a policy nomination, not an instruction to force lifecycle state. It
contains the installation, idempotency key, persona, branch, subject identity
and kind, semantic fields required by `NominationProposal`, a declared
selection basis and epistemic qualifiers, an optional visible evidence summary,
and its creation time. The operation is exactly `nominate`.

GitHub is restricted to explicitly non-sensitive proposals:

- `sensitivity` is exactly zero;
- visibility is `private_root` or `restricted`;
- global and scene-local scopes are forbidden;
- metadata cannot carry arbitrary producer extensions; and
- sealed payloads, ciphertext envelopes, credentials, hidden reasoning, raw
  transcripts, and evidence excerpts are forbidden.

An unknown sensitivity is not treated as zero. V1 objects seen by the live
poller, unknown schema versions, or V2 objects that violate this boundary are
quarantined or rejected before canonical policy evaluation. Adding a broader
sensitivity or scope profile requires a new proposal version and architecture
review.

### Immutable discovery and polling

The worker pins the GitHub repository numeric ID, owner/name, default branch,
installation path prefix, and installation UUID. A conditional ETag request
resolves one branch head commit. The worker enumerates the exact tree at that
commit and fetches blobs by immutable object identity; it never combines a
listing from one head with content from another.

Provider object identity is `(github, numeric repository ID, normalized
create-only path)`. The row also records the observed head commit and blob SHA.
The same object may be rediscovered only with identical immutable provenance
and bytes. A changed blob at an existing path is quarantined as an append-only
violation. Blob SHA alone is not object identity because distinct paths may
contain identical bytes.

Ingress discovery permits a nullable declared idempotency key and payload hash
only while an item is `discovered` or terminally `quarantined`. Validation may
set each field exactly once while moving the row from `discovered` to
`validated`; validated and accepted rows require both. Immutable provider,
repository, path, commit, blob, installation, actor, client, and binding fields
remain non-null and immutable. This is implemented by a reviewed migration and
database lifecycle barrier, never by placeholder keys or hashes.

### Processing and terminal states

The runtime adapter validates V2 and builds the existing policy-gated
`NominationProposal`. A trusted server resolver establishes only allowlisted
GitHub source facts. Caller-supplied evidence references are never upgraded to
trusted evidence. The resolver instead derives one stable, server-owned source
key from the pinned tenant, actor, client, transport binding, and numeric
repository identity. Proposal paths, blob and commit IDs, idempotency keys, and
credentials are excluded so repeated proposals from one authenticated GitHub
source cannot manufacture independent corroboration; exact object provenance
remains in the ingress ledger and event transaction. The worker invokes
`SelectionEngine` with the existing `memory:propose` scope and ingress ID. It
does not invoke legacy mutation-v1 or insert events, projections, decisions, or
receipts directly.

Ingress registration, validation, policy decision, command receipt, canonical
event when any, and terminal linkage retain their existing transaction and role
boundaries. Accepted candidate, active, or promoted outcomes become
`accepted`. An exact already-covered nomination becomes `duplicate` and links
to the existing canonical event and memory without creating a new event.
Policy omit or reject becomes `rejected` with an allowlisted code. Validation,
provenance, or append-only failures become `quarantined`. Conflict is reserved
for an explicit canonical conflict outcome. Every rediscovery or worker retry
loads the existing terminal row and performs no additional semantic mutation.

### Webhook wakeups

Webhooks are optional wake hints only. When enabled, the listener verifies a
strict body limit, media type, expected event, delivery UUID, pinned repository
and branch, and `X-Hub-Signature-256` HMAC over the exact raw bytes using
constant-time comparison. Delivery IDs are replay-protected for a bounded
period. A valid webhook wakes the normal conditional poller and then its body
is discarded; no webhook path, commit, or payload is accepted as canonical
provenance. Without a configured credential and binding, the listener is
disabled and fails closed.

### Privacy and operations

The GitHub token is read-only and loaded through a systemd credential. Logs and
errors contain only allowlisted IDs, lifecycle codes, counts, and timings. They
never contain proposal bodies, statements, reasons, evidence text, repository
URLs, authorization values, webhook signatures, or GitHub response bodies.
ETags are opaque worker checkpoint data, not authentication.

## Consequences

- Existing proposal-v1 bytes and Genesis import behavior remain unchanged.
- Producers need the checked-in V2 schema and exact canonical UUID anchors
  before a live proposal can be queued.
- Malformed objects can be represented honestly and quarantined without fake
  semantic metadata.
- Fifty-file concurrency and poll/webhook replay tests are release-blocking for
  enabling the service.
