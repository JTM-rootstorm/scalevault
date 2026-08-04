# ADR 0009: Canonical events and replay

- Status: Accepted
- Date: 2026-08-03
- Supersedes: None
- Extends: ADR 0002 and ADR 0003

## Context

Externally visible identifiers, idempotency, payload hashing, event order, and
projection bytes must remain stable across Python processes, PostgreSQL JSONB,
and archive export. Sorted-key `json.dumps` is not a complete cross-runtime
canonicalization algorithm, and identity sequences can expose an uncommitted
lower number after an exporter has checkpointed a higher committed number.

## Decision

### Identifiers and event order

ScaleVault-generated externally visible canonical IDs use RFC 9562 UUIDv7 with
a 48-bit Unix-millisecond timestamp and 74 cryptographically random bits.
UUIDs are identifiers, not semantic ordering. Clock rollback or multiple
same-millisecond IDs cannot change replay order.

`memory_events.sequence` is the sole replay and export order. A singleton
transactional counter allocates the next sequence as the final short ordering
step of an append transaction. Rollback restores the counter, and committed
events therefore form a gap-free prefix. This brief ordering lock is not a
global semantic or policy lock; Milestone 3 still uses aggregate-specific locks
for writes.

### Canonical JSON and hashes

Payload identity uses RFC 8785 JSON Canonicalization Scheme bytes after domain
normalization. Inputs must satisfy I-JSON and reject duplicate object names,
non-string keys, lone surrogates, non-finite numbers, excessive nesting, and
integers outside the interoperable safe range.

Normalization rules are versioned:

- UUIDs and hexadecimal hashes are lowercase strings;
- aware datetimes normalize to UTC with exactly six fractional digits and `Z`;
- semantic decimals are bounded and rendered as JSON numbers without redundant
  zeroes;
- Unicode strings are preserved without normalization;
- nullable contract fields are explicit `null`; and
- arrays preserve semantic order, while explicitly set-like collections sort
  by their documented stable key.

`payload_sha256` is SHA-256 over the canonical payload bytes. PostgreSQL stores
the 32 raw bytes; JSON boundaries render lowercase hexadecimal. PostgreSQL's
textual JSONB rendering is never hashed.

Each append also stores `command_sha256`, hashing the tenant, lineage, branch,
actor, client, operation and payload version, target memory, expected revision,
causation event, and payload. It excludes the idempotency key, correlation ID,
session, generated IDs, sequence, and server timestamp. Reusing an idempotency
key with different command bytes fails; matching bytes return the original
receipt.

### Event envelopes and payloads

The event envelope contains explicit schema and payload versions, immutable
identity and transport provenance, command and payload hashes, canonical
payload bytes, parsed JSONB, and a server timestamp. Unknown
`(operation, payload_version)` pairs fail closed.

Create operations contain a complete initial memory after-image. State-changing
operations contain the previous revision and complete resulting after-image.
Evidence, link, conflict, branch, tombstone, and purge operations contain their
complete normalized record or explicit retraction identities. Reducers never
call the clock, generate IDs, apply current policy, or infer missing defaults.

The event store preserves canonical bytes as the hash authority and verifies
that they decode to the same JSON value stored in JSONB. Event rows reject
update and delete through privileges and a database trigger.

### Deterministic projection rebuild

One pure reducer path serves live append and rebuild. It validates sequence,
envelope and payload versions, hashes, identity stability, exact revision
transitions, lifecycle transitions, and child-record identity reuse before
applying an event.

Rebuild creates semantic projections in an isolated target within one
transaction. It consumes only accepted events in sequence order and never
recreates outbox side effects or embeddings. Any invalid event aborts the whole
rebuild without exposing partial state.

Canonical projection comparison serializes a versioned aggregate containing
the memory plus sorted evidence, links, conflicts, and members. It excludes
search vectors, embeddings, database row order, leases, and rebuild-time data.
The pre-rebuild and rebuilt identity sets and RFC 8785 bytes must match exactly.

### Export checkpoints

A canonical manifest cannot include the Git commit SHA of the commit containing
that manifest without circularity. The manifest keeps that value absent or
null; PostgreSQL records the resulting commit SHA in the export checkpoint.

Checkpoints form a target-scoped chain with the source high-water sequence,
exported range and count, manifest hashes, lifecycle state, and resulting Git
SHAs. The exporter holds a target-scoped advisory lock and reconciles an
existing Git commit by manifest hash after a crash instead of creating a second
batch.

## Consequences

- The event counter briefly serializes only final ordering, preserving a safe
  checkpoint prefix.
- Canonicalization is a security dependency and needs official RFC vectors plus
  project-specific Unicode, number, timestamp, and tampering tests.
- Command receipts are part of Milestone 2 schema even though concurrent retry
  handling remains Milestone 3 work.
- Rebuild equivalence is measured with bytes and hashes, not ORM equality or a
  physical PostgreSQL dump.
