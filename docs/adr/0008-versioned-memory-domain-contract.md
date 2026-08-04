# ADR 0008: Versioned memory domain contract

- Status: Accepted
- Date: 2026-08-03
- Supersedes: None
- Extends: ADR 0002, ADR 0004, and ADR 0005

## Context

Milestone 2 creates the first durable semantic schema. Identity, ontology,
transport provenance, event payloads, and projection constraints must agree
before an initial migration can become a recovery contract. The pre-release
JSON schemas currently describe individual vocabularies but do not prevent
cross-tenant references or invalid combinations.

The proposal-ingress schema also uses transport-specific `ontology` and
categorical `confidence` fields, while the canonical projection uses
`ontological_status` and a numeric confidence score. Silently treating those
different concepts as equivalent would manufacture semantics.

## Decision

### Contract and migration ownership

The v1 ontology, operation vocabulary, relational schema, JSON schemas, domain
validators, and archive serializers are one versioned contract. A vocabulary
or compatibility change ships with its schema, migration, fixtures, and later
ADR. The pre-release memory event and projection v1 schemas may be tightened
before the first production event exists; after that point, breaking changes
require a new version.

PostgreSQL vocabulary columns use bounded text with named `CHECK` constraints.
They do not use mutable lookup rows or PostgreSQL native enums. Python enums and
JSON schemas must have parity tests against the SQL vocabulary.

The GitHub proposal v1 schema remains a transport DTO. Its `ontology` maps by
name to canonical `ontological_status`, but categorical confidence describes a
basis, not a numeric truth score. An ingress policy adapter must obtain or
derive the canonical score explicitly; it may not apply an undocumented numeric
mapping.

### Tenant and lineage isolation

Every tenant-owned table stores `tenant_id`. Semantic tables also store their
lineage and branch anchors where applicable. Parent tables expose composite
unique keys, and every tenant-local relationship uses tenant-qualified
composite foreign keys. UUID uniqueness alone is not considered sufficient
isolation.

Tenant tables enable and force PostgreSQL row-level security. Policies read a
transaction-local tenant setting established only after authentication. An
unset tenant sees and mutates no tenant rows. Runtime roles do not own tables,
hold `BYPASSRLS`, or receive unrestricted DDL rights.

Foreign keys default to `ON DELETE RESTRICT`. Identities and audit records are
retired, revoked, sealed, or tombstoned. Derived projection tables may be
cleared only by the controlled rebuild path.

### Required relational families

The initial schema contains:

- tenants, actors, clients, credentials, logical sessions, transport
  installations, immutable transport bindings, and ingress items;
- personas, lineages, branches, subjects, and subject aliases;
- the event-order counter, immutable memory events, and command receipts;
- memories, evidence, links, conflicts, and conflict members;
- memory content-key metadata without key material;
- an embedding-model registry without a physical vector table;
- transactional outbox jobs, archive targets, and export checkpoints; and
- the Alembic compatibility marker.

The initial migration creates no tenant, persona, client, or memory rows.
Synthetic identities belong in transactional test fixtures. Production
identity bootstrap remains an explicit operator action.

`vector`, `pg_trgm`, `citext`, and `pgcrypto` are elevated bootstrap
prerequisites. Alembic verifies their presence and versions but does not grant a
runtime role extension-install privileges. A physical `memory_embeddings_vN`
table is deferred until Milestone 4 selects and records the model artifact,
dimension, normalization, and distance metric.

### Structural semantic rules

The database and shared domain validator reject at least these combinations:

- `scene_local` without a matching origin session, or with `shareable` or
  `public_seed` visibility;
- `project`, `persona`, `relationship`, or episodic scope without the matching
  typed subject and structural anchor;
- `public_seed` unless status is `active`, sensitivity is zero, and an explicit
  publication approval is present;
- a visibility above the branch's explicit allowed-pair ceiling;
- links, evidence, conflicts, causation, sessions, or branch parents crossing
  tenant or lineage boundaries;
- non-internal events without a valid immutable transport binding;
- GitHub ingress events without an ingress item, or non-GitHub events carrying
  one; and
- hashes of the wrong length, invalid timestamp ranges, non-object metadata,
  non-array interpretation limits, invalid scores, and invalid lifecycle field
  combinations.

Category and ontological-status compatibility is closed in v1:

| Category | Allowed ontological status |
|---|---|
| `stable_fact` | `literal_user_fact`, `literal_technical_fact` |
| `user_preference` | `literal_user_fact`, `uncertain` |
| `assistant_preference_like_pattern` | `assistant_self_description`, `observed_assistant_behavior`, `hypothesis`, `uncertain` |
| `boundary_or_permission` | `literal_user_fact`, `interaction_convention`, `uncertain` |
| `interaction_convention` | `interaction_convention`, `literal_user_fact`, `uncertain` |
| `relationship_pattern` | `observed_assistant_behavior`, `interaction_convention`, `hypothesis`, `uncertain` |
| `emergent_tendency` | `assistant_self_description`, `observed_assistant_behavior`, `hypothesis`, `uncertain` |
| `episodic_anchor` | all statuses except `hypothesis` |
| `project_decision`, `project_state` | `literal_technical_fact`, `uncertain` |
| `procedure` | `literal_technical_fact`, `interaction_convention`, `uncertain` |
| `open_question`, `interpretation` | `hypothesis`, `uncertain` |
| `external_fact` | `literal_technical_fact`, `hypothesis`, `uncertain` |

The shared validator owns meaning-sensitive checks; the database duplicates
stable structural checks as a final barrier. Events record the policy version
under which they were accepted so replay never reruns a later policy.

### Transport provenance

Each event references an immutable transport binding that resolves the actor,
client, transport kind, disclosure boundary, and installation where required.
The canonical transport kinds are `direct_private`, `secure_tunnel`, `relay`,
`github_ingress`, `internal_service`, and `archive_restore`.

- Direct private clients may use authorized normal and administrative domain
  operations.
- Secure tunnel and relay clients use only their authenticated non-admin scopes;
  relay events require an installation binding.
- GitHub ingress accepts observe/remember proposals only, forbids `global` and
  `scene_local`, and records the GitHub disclosure boundary permanently.
- Internal services may execute only their named worker responsibilities.
- Archive restore is unavailable through online MCP and is isolated from normal
  mutation paths.

Visibility and disclosure are separate. A private visibility label never
claims that data did not cross a consented transport boundary.

### Events, projections, and erasure

Accepted memory events are append-only. Current memories and their evidence,
links, and conflict rows are derived projections and never the sole copy of a
durable semantic fact. A full rebuild covers those semantic projections and
event-sourced branches; identities, ingress bookkeeping, embeddings, outbox
delivery state, and export checkpoints remain operational/reference state.

The event vocabulary adds `evidence_attached`, `evidence_redacted`, `unlinked`,
and `payload_purge_completed` so all semantic projection changes are replayable.
Every operation has a closed, versioned payload containing complete normalized
after-images or explicit retraction identities.

Hard forget is cryptographic erasure for protected content: stop retrieval,
destroy the per-memory key outside PostgreSQL, remove sensitive derivatives,
and retain only safe tombstone and destruction-receipt metadata. Content-key
rows store provider references and lifecycle state but never key material.
Logical tombstoning remains distinct from verified key destruction.

## Consequences

- The initial migration is intentionally broad because it freezes one coherent
  recovery contract before data exists.
- Composite foreign keys and row-level policies add schema verbosity in return
  for structural tenant isolation.
- Proposal v1 ingestion needs an explicit adapter rather than a lossy field
  rename.
- Embedding storage cannot land until a model contract is selected.
- Hard-forget behavior depends on a future external key facility and purge
  worker; the initial schema preserves that path without claiming it is active.
