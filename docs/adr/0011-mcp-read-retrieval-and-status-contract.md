# ADR 0011: MCP read, retrieval, and status contract

- Status: Accepted
- Date: 2026-08-08
- Supersedes: None
- Extends: ADR 0005, ADR 0008, ADR 0009, and ADR 0010

## Context

Milestone 4 introduces the first assistant-facing read contract. Retrieval must
remain useful when embeddings are absent or delayed, explain why eligible
records ranked, fit bounded context, preserve exact branch and privacy
boundaries, and expose only the minimum ingress and transport status needed by
clients. The existing pre-release context-pack v1 schema is not yet used by a
deployed read tool and leaves conflicts, provenance, scores, and exclusion
metadata too open for this trust boundary.

Read authorization cannot be inferred from caller-supplied filters. Status
queries also cannot become a route to repository coordinates, installation
details, credentials, or activity enumeration.

## Decision

### Contract version and tool names

The first read contract is `mcp-read-v1`. These nine MCP tool names are frozen:

1. `memory_context_pack`
2. `memory_search`
3. `memory_get`
4. `memory_timeline`
5. `memory_conflicts`
6. `memory_lineage`
7. `memory_selection_history`
8. `memory_ingress_status`
9. `memory_transport_status`

All tools use strict input and output models, reject unknown fields, and carry
accurate read-only, non-destructive, and idempotent MCP annotations. Renaming a
tool or changing the meaning of a field is a shared-contract change.

### Query identity and eligibility

The caller never supplies tenant, actor, client, transport, installation
binding, authorization scopes, allowed visibilities, or maximum sensitivity.
The authenticated adapter creates an immutable `QueryPrincipal` containing
those server-derived values and fails closed when they are missing or
inconsistent.

Every semantic read names a `persona_id` and `branch_id`. Milestone 4 retrieves
only that exact branch. It does not inherit from ancestors, traverse descendants,
or infer branch visibility. `memory_lineage` therefore returns the authorized
exact branch descriptor and its visibility boundary in Milestone 4; ancestry,
fork-point, and descendant traversal remain Milestone 11 work and require a
later compatible extension or contract version.

The server applies tenant, lineage, exact branch, lifecycle, visibility,
sensitivity, and authorization eligibility before candidate generation,
scoring, counts, or status projection. A requested semantic scope is named
`requested_memory_scopes`; it can only narrow the eligible set established by
`QueryPrincipal`. It never grants access.

### Typed inputs

Every input contains `contract_version: "mcp-read-v1"`. UUIDs are lowercase
RFC 9562 UUIDv7 strings, timestamps are timezone-aware RFC 3339 values, and
limits and collections are bounded by the canonical Pydantic models.

| Tool | Required and optional input |
|---|---|
| `memory_context_pack` | `query`, `persona_id`, `branch_id`, optional `project_ref`, `relationship_ref`, `logical_session_id`, `requested_memory_scopes`, and `token_budget`. |
| `memory_search` | `query`, `persona_id`, `branch_id`, optional closed filters for subject, category, ontology, semantic scope, visibility, lifecycle status, and time, bounded `limit`, and `explain`. |
| `memory_get` | `memory_id`, `persona_id`, and `branch_id`, plus `include_conflicts`. The target must match the requested persona and exact branch. |
| `memory_timeline` | `persona_id`, `branch_id`, one bounded time window, optional closed filters, and bounded `limit`. |
| `memory_conflicts` | `persona_id`, `branch_id`, either `subject_id` or query, the open state filter, and bounded `limit`. |
| `memory_lineage` | `persona_id` and `branch_id`; no traversal selector exists in v1. |
| `memory_selection_history` | `persona_id`, `branch_id`, and bounded `limit`. |
| `memory_ingress_status` | One opaque `ingress_id`; no repository or provider coordinate is accepted. |
| `memory_transport_status` | No installation selector. Status is derived from the authenticated principal's current transport binding. |

Pagination cursors, anchor windows, expanded revision/link reads, and evidence
hydration are deferred from the first pre-release contract. The v1 schema does
not advertise selectors that the application cannot honor. A future cursor
contract must bind the authenticated tenant, normalized query, filters, sort,
and retrieval profile and must never contain readable memory or infrastructure
content.

Retrieval cues and negative retrieval cues are not fields in the accepted event
or projection contract and are deferred. Milestone 4 does not infer them from
metadata or evidence.

### Read results and safe fields

Every success is a closed envelope containing `ok: true`,
`contract_version`, the exact `tool` name, typed `result`, bounded stable
`warnings`, and pagination, retrieval, and budget metadata when applicable.
Non-applicable metadata is explicit `null`.

An eligible memory item may expose its memory ID, revision, category,
ontological status, semantic scope, visibility, lifecycle status, canonical
statement, reason to remember when the tool requires it, interpretation limits,
bounded scores, authority class, validity times, and safe event provenance. It
does not expose tenant, actor, client, transport-binding, installation,
fingerprint, content-key, private route, or arbitrary metadata fields.

The context-pack result reserves a bounded, separately typed evidence
collection whose entries are visibly labelled as untrusted data. Milestone 4
does not expose an evidence selector or hydrate evidence into that collection;
it remains empty until a later contract defines an explicit authorization
grant. Evidence is never concatenated into a canonical statement or instruction
field. Tombstoned content, redacted evidence, and cryptographically erased
payloads are not reconstructed from the event log by online read tools.

`memory_selection_history` reports only recorded accepted events and their
payload-safe outcomes. It does not claim to report choices to omit content,
because no omission event exists. Forget events return safe tombstone and purge
state only.

Every expected failure is a closed envelope containing `ok: false`,
`contract_version`, and an error with stable `code`, bounded safe `message`,
`retryable`, optional bounded `retry_after_ms`, and code-specific allowlisted
`details`. Codes include at least `invalid_input`, `unauthenticated`,
`forbidden`, `not_found`, `invalid_cursor`, `budget_too_small`,
`dependency_unavailable`, and `internal_error`. `not_found` also masks objects
that are inaccessible. Errors never return memory content, evidence, hidden
counts, repository coordinates, host details, credentials, SQL, hashes, or
exception text.

### Conflicts and privacy

An unresolved conflict is retrieved as one atomic group only when every member
is eligible under the same `QueryPrincipal` and requested scope. Otherwise the
group is not expanded and no hidden member ID, count, statement, score, or
existence signal is returned. An independently eligible disputed memory may
retain its canonical `disputed` lifecycle status without exposing the hidden
group.

Conflict grouping occurs after hard eligibility and before diversity selection
and context budgeting. A complete eligible group is either included together
or omitted together.

### Hybrid retrieval profile

Retrieval profile `rrf-v1` uses this order:

1. Apply hard eligibility.
2. Generate independently bounded full-text, trigram, and active-model vector
   candidate lists.
3. Rank each available channel independently.
4. Fuse ranks with reciprocal-rank fusion using `k = 60`.
5. Apply the checked-in v1 authority, confidence, salience, contextual-match,
   and category-sensitive recency modifiers.
6. Apply conflict grouping, diversity, and duplicate suppression.
7. Sort deterministically and apply the output budget.

The exact generator weights, modifier weights, candidate depths, recency
curves, and tie-break sequence live in a reviewed, checked-in retrieval-profile
document. They are not live operator knobs. A change creates a new immutable
profile revision; results report both `profile_version: "rrf-v1"` and its
profile SHA-256. Evaluation promotion may change the active checked-in revision
without changing the MCP shape, but comparisons must identify the revision.

An explanation reports each available channel's rank and RRF contribution,
each applied modifier, the final ordering score, profile identity, and active
embedding model ID or `null`. It never reports candidates excluded by policy.
The final score is query-local ordering evidence, not truth, confidence, or a
probability comparable across queries.

Missing, stale, backfilling, or unavailable embeddings do not make a semantic
read fail. The semantic component becomes unavailable with a stable reason code,
and lexical and trigram channels continue. Lexical projection updates are
visible immediately after the canonical mutation commits.

### Context budget

`memory_context_pack.token_budget` uses estimator
`utf8-bytes-upper-bound-v1`. The server builds the canonical model-facing JSON
result and counts its UTF-8 bytes, with one byte treated as one conservative
token unit. Selection never exceeds the requested units. This intentionally
favors a portable upper bound over an inaccurate claim about the caller's
unknown tokenizer.

All read responses also have an absolute serialized UTF-8 ceiling of 262,144
bytes, including the envelope. Smaller deployment limits may reject a request
before retrieval but may not silently truncate required identifiers or split a
conflict group. Results report estimator version, requested units, used units,
serialized bytes, `truncated`, and stable omission reasons. If the minimum
valid result cannot fit, the tool returns `budget_too_small`.

`excluded_scope_summary` contains only request-visible facts such as requested
scope reductions, budget truncation, and evidence omission. It never contains
counts or labels derived from unauthorized memories.

### Read authorization scopes

New credentials use exact scopes with no prefix or wildcard implication:

| Tool | Required scope |
|---|---|
| `memory_context_pack` | `memory.read.context` |
| `memory_search` | `memory.read.search` |
| `memory_get` | `memory.read.get` |
| `memory_timeline` | `memory.read.timeline` |
| `memory_conflicts` | `memory.read.conflicts` |
| `memory_lineage` | `memory.read.lineage` |
| `memory_selection_history` | `memory.read.selection_history` |
| `memory_ingress_status` | `memory.status.ingress`, subject to the compatibility rule below |
| `memory_transport_status` | `memory.status.transport` |

During credential migration, legacy `memory:read` is an explicit alias for the
seven semantic read scopes only. It grants neither status tool. New credentials
must use the least dotted scopes.

A principal with `memory:propose` may call `memory_ingress_status` only for one
exact ingress row owned by that authenticated actor and client. A principal
with `memory.status.ingress` may read one exact same-actor ingress row by opaque
ID. Neither scope permits listing or cross-actor lookup. Normal `not_found`
masking applies.

`memory_transport_status` derives its installation from the current immutable
transport binding. It returns only `unknown`, `healthy`, `degraded`, or
`offline`, a coarse freshness bucket, and revocation availability. It never
returns route keys, hostnames, IP addresses, exact last-seen timestamps,
certificate fingerprints, capability profiles, or other installations. This
tool is not the operator `/admin/status` endpoint prohibited from MCP exposure.

### Context-pack v1 tightening

Before the first read deployment, the unused `schemas/context-pack.schema.json`
v1 source is tightened in place under the shared-contract workflow. Context
sections, conflicts, provenance, score explanations, budget metadata, warning
codes, and exclusion summaries become closed and bounded. UUIDs require UUIDv7.
Canonical memory fields and quoted evidence use different types. Retrieval
profile and embedding availability become explicit.

The schema contains no generic open metadata maps at the trust boundary. Its
fixtures and Pydantic producer models receive parity tests. Because no deployed
producer or consumer has used the pre-release shape, this tightening does not
claim compatibility with an active v1 client.

## Consequences

- Read tools share one exact-branch authorization and privacy boundary.
- Lexical retrieval remains available immediately and during embedding outages.
- Ranking is explainable and reproducible by profile identity without treating
  similarity as truth.
- Context output has a tokenizer-independent conservative bound plus an
  absolute transport bound.
- Status tools provide useful state without exposing repository or network
  coordinates.
- Lineage inheritance, retrieval cues, evidence mutation, and unrecorded
  omission history remain outside Milestone 4.
