# ADR 0013: Versioned selection policy and candidate lifecycle

- Status: Accepted
- Date: 2026-08-08
- Supersedes: None
- Extends: ADR 0005, ADR 0008, ADR 0009, ADR 0010, and ADR 0011

## Context

Milestone 5 makes memory selection a durable policy decision rather than a
choice implicit in a caller-selected mutation tool. The mutation v1 contract
always creates an active memory for `memory_remember` and a candidate for
`memory_observe`. It has no typed evidence input. The read v1 selection-history
tool is an eligible current-memory event timeline, so it cannot represent an
omission and loses history when the current projection becomes ineligible.

Candidate promotion and expiry also change canonical lifecycle state. Updating
only the projection or an outbox row would make replay, archive history, and
selection history disagree. A private seed has the same authority problem: a
reviewed bundle is input to policy evaluation, not a license to insert canonical
rows directly.

## Decision

### Canonical selection profile

The first machine-readable profile is `selection-v1`. Its canonical source is
`services/memory-node/src/kivra_memory/policy/profiles/selection-v1.json`, and
its contract is `schemas/memory-selection-policy-v1.schema.json`. The profile
identity is lowercase SHA-256 over RFC 8785 canonical bytes of the complete,
validated profile. The accepted profile digest is
`b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e`.
The digest is external to the profile to avoid a self-referential hash.

The profile is a fixed table, not a general expression language. It contains:

- one rule for every closed selection basis;
- one guardrail for every closed content signal;
- closed outcomes `omit`, `candidate`, `active`, and `reject`;
- typed evidence requirements, epistemic qualifiers, reason codes, and
  candidate lifetimes; and
- the exact precedence `structural`, `hard_guardrail`, `evidence`, `basis`,
  then `qualification`.

Unknown profile versions, missing basis or guardrail coverage, duplicate rule
identifiers, invalid candidate lifetimes, or a digest mismatch fail closed. A
profile change creates a new immutable profile version and evaluation baseline;
it is not a live operator knob. Accepted events and selection decisions retain
the profile identity used at decision time. Replay applies recorded outcomes
and never reruns current policy.

The policy evaluator consumes structured facts and does not classify prose.
An authenticated adapter and server-side resolver establish effective authority,
evidence kind and trust, and any content signals. Ordinary MCP callers may
propose selection basis, semantics, evidence references, and epistemic
qualifiers, but may not assert effective authority, trusted evidence,
classifier output, or content signals. Missing or unresolved trusted facts
produce `authority_not_established`, another fail-closed result, or a candidate
only where the profile explicitly permits one. Until trusted request-scoped
resolution exists for a transport, that transport cannot claim semantic policy
classification from raw text.

### Selection decisions

Every evaluation appends one immutable selection decision, including omissions
and rejections. A decision stores only bounded, safe audit facts:

- a UUIDv7 decision ID and transactionally allocated stable selection sequence;
- tenant, lineage, branch, and persona anchors;
- private actor, client, and transport-binding provenance;
- the copied authorization anchors `selection_basis`, `scope`, `visibility`,
  `sensitivity`, `subject_id`, and `subject_kind`;
- profile version and digest, matched rule identifiers, outcome, and safe reason codes;
- a canonical input digest; and
- nullable canonical memory and event references.

It stores no statement, evidence excerpt, free-text rationale, arbitrary
metadata, credential, route, or host detail. `candidate`, `active`, `promoted`,
and `expired` decisions require memory and event
references. `omit` and `reject` decisions require both references to be null.
Copied authorization anchors are mandatory even without a Memory row so a read
can apply scope, visibility, sensitivity, subject, tenant, persona, and exact
branch filters before revealing that a decision exists. The private provenance
fields are never exposed by assistant-facing reads.

Selection decisions use forced row-level security, tenant-qualified foreign
keys, append-only privileges, and update/delete rejection. Their ordering is
separate from canonical memory-event replay ordering. An accepted nomination
commits its event, projection, decision, receipt, and outbox work in one
`SERIALIZABLE` transaction. An omitted or rejected nomination commits its
decision and receipt in one transaction.

Command receipts retain the existing `(tenant_id, client_id, idempotency_key)`
namespace. A nomination receipt identifies exactly one terminal decision and
may have no event. Replaying an omitted request returns the original omission;
it cannot later create a memory under the same key.

### Mutation v2 and the v1 compatibility boundary

The policy entry point is `memory_nominate` under `mcp-mutation-v2`. The
authenticated adapter resolves trusted facts, constructs the internal selection
request, invokes the selection engine, and executes the recorded outcome through
the same transport-neutral command and event boundary used by direct, relay,
ingress, and seed adapters.

The wire input never accepts lifecycle status, candidate deadline, effective
authority, evidence trust, content signals, classifier results, policy outcome,
rule identity, or profile digest. Server-owned outcomes cannot be upgraded by a
caller. Errors and safe results do not reflect statements, evidence, or
rationale prose.

After Milestone 5 activation, `memory_observe`, `memory_remember`, and semantic
`memory_revise` from `mcp-mutation-v1` are not ordinary policy entry points.
Their wire and replay contracts remain readable for compatibility, but execution
requires a non-default legacy-migration capability and is restricted to
`direct_private` or a specifically authorized `internal_service`. Normal direct,
relay, ingress, and seed clients receive no such capability. The legacy
`memory:write` alias cannot bypass selection policy. All new selection uses
`memory_nominate` and the selection engine.

### Promotion and expiry

New candidates record `candidate_expires_at` in their canonical after-image.
The field is nullable only for legacy v1 events and non-candidate states. A new
candidate decision requires a deadline derived from its recorded profile.
Promotion and expiry clear the deadline in the resulting active or retired
after-image; the originating candidate event preserves the historical value.

Candidate creation schedules the already-reserved `expire_candidate` outbox job
at the deadline. Candidate reevaluation and expiry run under narrowly authorized
`internal_service` principals and use deterministic idempotency keys bound to
profile digest, memory ID, and expected revision. Each handler locks and checks
the exact tenant, lineage, branch, candidate status, revision, and deadline.
A stale job after promotion, revision, dispute, retirement, or forgetting is an
idempotent no-op.

Promotion and expiry are distinct canonical v2 operations:

- `candidate_promoted` changes `candidate` to `active`; and
- `candidate_expired` changes `candidate` to `retired`.

Their v2 payloads contain the previous revision, complete resulting after-image,
selection-decision ID, and safe policy rule code. They are not encoded as
generic revision or human-requested retirement. Event readers and reducers must
support existing v1 bytes and new v2 operations without rewriting v1 history.
Projection rebuild applies the recorded transition and never reevaluates policy.

### Selection-history v2

The authoritative Milestone 5 selection-history surface is the new read-only
tool `memory_selection_decisions` under `mcp-read-v2`. It is backed by immutable
selection decisions, not a join from events to current Memory rows. It returns
only decision sequence and ID, decision time, outcome, safe reason and rule
codes, profile version and digest, and authorized nullable memory/event IDs.
Content remains available only through the separately authorized memory read.

Eligibility is evaluated from the decision's copied authorization anchors before
ordering, counts, or projection. The result never exposes statements, rationale,
evidence, hidden counts, actor/client/binding identities, classifier facts, or
arbitrary metadata. `memory_selection_history` under `mcp-read-v1` remains a
byte-shape-frozen accepted-event compatibility surface and must not emit new
operation values outside its accepted vocabulary.

### Operator-local private seed

`schemas/private-seed-v1.schema.json` defines the strict input contract for a
reviewed private seed. Real seed bundles and memory payloads remain outside this
repository on operator-controlled storage with restrictive permissions. The
repository contains only the schema, importer, and synthetic/redacted fixtures.

A bundle uses symbolic tenant, persona, lineage, branch, and subject selectors.
The authorized operator-side service resolves them at apply time and fails
closed on absence, ambiguity, retirement, sealing, or visibility mismatch.
Deploy-specific UUIDs, reviewer actor IDs, credentials, hostnames, and route data
do not belong in the bundle. Seed visibility is limited to `private_root` or
`restricted`; `scene_local` and `public_seed` are forbidden. Public-seed
promotion remains Milestone 11 work.

Review is an apply-time operator gate, not a self-asserted field in the bundle.
The workflow first validates and secret-scans the complete bundle, renders a
content-free plan and domain-separated digest, and then requires explicit
approval bound to that exact digest. Import uses deterministic per-record
idempotency keys and the same nomination/selection service as other transports.
It never inserts projections directly, runs from a migration, or uses archive
restore as an authority shortcut. Selection history records the resulting seed
decisions without exposing seed content.

## Consequences

- Selection is reproducible and inspectable without turning prose into an
  executable policy language.
- Omissions become auditable while copied authorization anchors prevent
  same-branch omission side channels.
- Promotion and expiry remain replayable semantic changes rather than mutable
  worker state.
- Mutation v1 compatibility cannot act as an undeclared policy bypass.
- A private seed can be reviewed and applied without committing private memory
  payloads or deployment identifiers.
- The additional decision ledger, event version, receipt shape, and lifecycle
  workers increase migration and compatibility work, but keep transport,
  privacy, and recovery boundaries coherent.
