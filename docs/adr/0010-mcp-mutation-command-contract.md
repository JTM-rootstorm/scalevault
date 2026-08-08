# ADR 0010: MCP mutation and domain command contract

- Status: Accepted
- Date: 2026-08-08
- Supersedes: None
- Extends: ADR 0002, ADR 0004, ADR 0007, ADR 0008, and ADR 0009

## Context

Milestone 3 introduces concurrent mutation through MCP while preserving a
single canonical event and projection engine. Tool names, authorization,
idempotency, optimistic concurrency, retry behavior, and safe responses must
mean the same thing for direct, tunnel, relay, and future ingress adapters.
Transport-specific handlers would otherwise drift into separate authorities.

The deployment boundary also needs one clarification. The Memory Node's LXC
root storage is appropriate for installed software and small replaceable
application state, but it is not the fallback location for durable or
capacity-heavy ScaleVault data.

## Decision

### Version and tool names

The first mutation contract is `mcp-mutation-v1`. Its eight ordinary MCP tool
names are frozen exactly as follows:

1. `memory_observe`
2. `memory_remember`
3. `memory_revise`
4. `memory_link`
5. `memory_open_conflict`
6. `memory_resolve_conflict`
7. `memory_retire`
8. `memory_forget`

Renaming a tool, changing the meaning of an existing field, or changing a
closed vocabulary is a shared-contract change. Additive optional fields may be
introduced only when old consumers can ignore them safely. Otherwise a new
contract version is required.

All inputs and outputs are strict JSON objects. Unknown fields are rejected.
UUID fields are lowercase RFC 9562 UUIDv7 strings. Revisions are positive JSON
integers no greater than `2^53 - 1`. Timestamps, where accepted, are
timezone-aware RFC 3339 values and normalize according to ADR 0009. Text and
collection bounds belong in the canonical Pydantic command models. Those models
are the schema source for `mcp-mutation-v1`; MCP discovery input schemas and
`outputSchema` are contract-tested renderings of the same invariants. Adding a
checked-in JSON Schema source later follows the shared-contract workflow and
must not create a divergent definition.

### Authentication and common command envelope

Every tool accepts these common fields at its top level:

| Field | Type | Rule |
|---|---|---|
| `contract_version` | literal `mcp-mutation-v1` | Required. |
| `idempotency_key` | string, 1 to 255 characters | Required and opaque to the server. |
| `logical_session_id` | UUID or `null` | Optional continuity and audit context, not authentication. |
| `persona_id` | UUID | Required target persona. |
| `branch_id` | UUID | Required target branch. |
| `reason` | non-empty string | Required rationale for the attempted mutation. |
| `causation_event_id` | UUID or `null` | Optional same-tenant causal event. |

The caller never supplies tenant, actor, client, transport kind, installation,
authorization scope, or transport binding in tool arguments. The authenticated
adapter resolves those values, fails closed if they are absent or inconsistent,
and passes an immutable `CommandPrincipal` to the command engine. Persona,
lineage, branch, session, causation, and target records are then resolved and
validated within that authenticated tenant.

`reason` participates in normalized command/receipt hashing and policy
validation, but event schema v1 has no generic command-reason field and does
not persist it as a separate event-envelope value. It is sensitive content and
is not written to ordinary request logs or reflected in generic errors.

### Typed operation inputs

The common fields are combined with exactly one of these operation payloads:

| Tool | Required operation fields | Concurrency rule |
|---|---|---|
| `memory_observe` | `memory`: `MemoryInputV1` | Create; `expected_revision` is forbidden. The server assigns `candidate` status. |
| `memory_remember` | `memory`: `MemoryInputV1` | Create; `expected_revision` is forbidden. The server assigns `active` status. |
| `memory_revise` | `memory_id`, `expected_revision`, `changes`: `MemoryRevisionInputV1` | The target revision must match exactly; `changes` must contain at least one mutable field. |
| `memory_link` | `source_memory_id`, `source_expected_revision`, `target_memory_id`, `target_expected_revision`, `link_type`, optional bounded `metadata` | Append-only relationship creation. Both target revisions must match. |
| `memory_open_conflict` | `subject_id`, `members`, `conflict_reason` | `members` contains 2 to 32 unique `{memory_id, expected_revision}` objects. All revisions must match. |
| `memory_resolve_conflict` | `conflict_id`, `members`, `resolution_kind`, `resolution_rationale`, `user_confirmed` | `members` contains the complete member set as `{memory_id, expected_revision, disposition, resulting_status}`. The conflict must still be open and all revisions must match. |
| `memory_retire` | `memory_id`, `expected_revision` | The target revision must match exactly. |
| `memory_forget` | `memory_id`, `expected_revision`, `mode`, `confirmation` | The target revision must match exactly; confirmation rules below apply. |

`MemoryInputV1` carries the canonical v1 creation fields from ADR 0008: typed
subject, category, ontological status, scope, visibility, statement, reason to
remember, interpretation limits,
confidence, salience, durability, sensitivity, authority class, temporal and
origin context, and bounded metadata. It does not accept server-owned IDs,
revisions, status, timestamps, fingerprints, publication approval,
content-key metadata, or transport provenance. `memory_observe` always creates
a candidate and `memory_remember` always creates an active memory; the caller
cannot force lifecycle or publication state.

`MemoryRevisionInputV1` is a strict, non-empty patch over mutable semantic
fields. Omission means unchanged; explicit `null` is accepted only for fields
that are nullable in ADR 0008. It cannot change identity, tenant, lineage,
branch, subject, scope, origin session, revision, creation time, lifecycle
state, transport provenance, or server-owned protection and publication
fields. Moving a claim to another structural scope requires a new memory and
an explicit typed relationship; revision never rewrites the claim's identity.

Conflict-resolution `resulting_status` is limited to `active`, `superseded`, or
`retired`. `user_confirmed` must be true when policy requires explicit user
confirmation for identity or relationship facts. Initial evidence is not part
of `mcp-mutation-v1`; evidence attachment and redaction require a later additive
or versioned tool contract rather than an implicit side effect of these tools.

Tool schemas use the closed vocabularies already owned by the v1 domain
contract. They do not duplicate or privately extend those values.

### Forget confirmation and completion

`memory_forget.mode` is exactly `logical` or `hard`. Confirmation is not a
generic boolean:

- logical forget requires `confirmation: "confirm_logical_forget"`;
- hard forget requires `confirmation: "confirm_hard_forget"`.

The client must present a confirmation that names the selected mode and its
consequences before setting the matching literal; switching modes requires a
new confirmation. A missing or mismatched literal fails before mutation.
Logical forget commits a
tombstone that stops normal retrieval while preserving the event history
permitted by policy. Hard forget commits the hard-forget request and tombstone,
then schedules key destruction and derivative purge transactionally. Its
successful tool result reports `forget_state: "purge_pending"`; it must not
claim cryptographic erasure until a later verified
`payload_purge_completed` event exists. If the memory is not protected by a
destroyable per-memory key, hard forget fails closed as `hard_forget_unavailable`.

### Success and error envelopes

Every successful mutation returns this closed envelope:

```json
{
  "ok": true,
  "contract_version": "mcp-mutation-v1",
  "operation": "remember",
  "receipt_id": "019c...",
  "event_id": "019c...",
  "memory_id": "019c...",
  "revision": 1,
  "idempotent_replay": false,
  "conflict_id": null,
  "conflict_state": null,
  "forget_state": null,
  "warnings": []
}
```

`operation` is one of `observe`, `remember`, `revise`, `link`,
`open_conflict`, `resolve_conflict`, `retire`, or `forget`. Fields that do not
apply are explicit `null`; `memory_id` and `revision` are `null` for an
aggregate-only result. `conflict_state` is `open` or `resolved` when applicable.
`forget_state` is `logically_forgotten` or `purge_pending` when applicable.
Warnings are bounded stable codes, not free-form memory content.

Every expected domain or availability failure returns this closed envelope:

```json
{
  "ok": false,
  "contract_version": "mcp-mutation-v1",
  "error": {
    "code": "stale_revision",
    "message": "The target changed after the supplied revision.",
    "retryable": false,
    "retry_after_ms": null,
    "details": {
      "memory_id": "019c...",
      "expected_revision": 4,
      "current_revision": 5,
      "suggested_action": "read_then_retry_or_open_conflict"
    }
  }
}
```

Stable error codes include at least `invalid_input`, `unauthenticated`,
`forbidden`, `not_found`, `stale_revision`, `idempotency_key_reused`,
`conflict_state_changed`, `hard_forget_unavailable`,
`serialization_exhausted`, `dependency_unavailable`, and `internal_error`. MCP
protocol failures may wrap this object, but adapters must preserve the
structured data.

Error `details` is allowlisted by code. Safe fields are opaque canonical IDs,
expected/current revisions, stable state codes, missing scope names,
`suggested_action`, and bounded retry timing. Errors never include memory
statements, reasons, evidence excerpts, metadata, command hashes, credentials,
private hostnames, SQL text, or exception text. In particular,
`stale_revision` exposes the current revision and a suggested action, not the
current or proposed claim. An authorized client may use a read tool to fetch
content separately. `not_found` is also used where distinguishing absence from
inaccessibility would disclose another tenant or scope.

Unexpected internal failures expose only the generic `dependency_unavailable`
or `internal_error` mapping; detailed exception data and internal correlation
remain in privacy-safe operator telemetry. The v1 public error envelope has no
correlation field.

### Idempotency and serializable retries

The idempotency namespace is exactly `(authenticated tenant_id,
authenticated client_id, idempotency_key)`. The server hashes normalized
command material as specified by ADR 0009. Repeating the same command returns
the original persisted success envelope with `idempotent_replay: true` and
creates no event or outbox job. Reusing the key for different command material
returns `idempotency_key_reused` and reveals neither hash nor prior content.
Logical session, transport session, relay request, and ingress provider IDs do
not widen or replace this namespace.

The command engine runs each mutation in a PostgreSQL `SERIALIZABLE`
transaction. It retries SQLSTATE `40001` by restarting the entire transaction,
re-resolving current state and locks, and rechecking the receipt. There are at
most four total transaction attempts. Before attempts two through four it uses
full jitter with maximum delays of 25, 50, and 100 milliseconds respectively.
No partial event, projection, receipt, or outbox result may escape a rolled-back
attempt. After the fourth serialization failure it returns
`serialization_exhausted`, `retryable: true`, and a bounded
`retry_after_ms` from 100 through 1000 milliseconds; callers retry with the
same idempotency key. Other database failures are not mislabeled as
serialization conflicts.

Concurrent attempts with the same namespace serialize on the receipt's unique
constraint or equivalent narrow lock. The loser loads and compares the winning
receipt rather than appending another event.

### Authorization scopes

New credentials use these exact dotted write scopes:

| Tool | Required scope |
|---|---|
| `memory_observe` | `memory.write.observe` |
| `memory_remember` | `memory.write.remember` |
| `memory_revise` | `memory.write.revise` |
| `memory_link` | `memory.write.link` |
| `memory_open_conflict` | `memory.write.conflict.open` |
| `memory_resolve_conflict` | `memory.write.conflict.resolve` |
| `memory_retire` | `memory.write.retire` |
| `memory_forget` | `memory.write.forget` |

Scope comparison is exact; there is no prefix or wildcard implication. During
the v1 credential migration only, the existing `memory:write` scope is an
explicit compatibility alias granting all eight scopes. New credentials must
not be issued with that broad alias, and credential migration must replace it
with the least set of dotted scopes. `memory:propose` remains an ingress-only
capability and grants none of the MCP mutation tools. Inside the shared command
engine it authorizes only `observe` or `remember`, only when an authenticated
principal carries a non-null validated ingress identifier; the event store
still enforces the GitHub binding, installation, declared idempotency key, and
validated ingress-row contract.

Authentication, transport restrictions, branch visibility ceilings, sensitivity
rules, and confirmation requirements are cumulative with scopes. A scope alone
never bypasses ADR 0008 policy.

Retire and forget commands reject a currently disputed memory with
`conflict_state_changed`. The caller must resolve its open conflict first so a
terminal transition cannot strand an unresolvable conflict set.

### Adapter-neutral command engine and ingress seam

MCP handlers are adapters: validate the wire shape, attach the authenticated
`CommandPrincipal`, construct one typed domain command, invoke the command
engine, and map its typed result. They do not insert events, update projections,
open conflicts, or enqueue work directly.

The command engine has no MCP, HTTP, relay, or GitHub provider types in its
interface. It accepts the principal plus one of the eight typed commands and
returns the success/error union above. Direct, tunnel, relay, and future ingress
paths must use this same engine and transaction boundary.

Milestone 3 supplies and tests this transport-neutral invocation seam, including
a synthetic externally-ingested command path. Milestone 6 owns GitHub polling,
provider-object deduplication, proposal-schema adaptation, quarantine,
acknowledgement, and production ingress wiring. Milestone 3 does not broaden
GitHub proposal operations beyond observe and remember, nor claim the Milestone
6 ingress worker is deployed.

### Storage-boundary clarification

ADR 0007 is refined as follows:

- Python virtual environments, installed application code, package caches,
  sockets, and small replaceable application state may remain on the LXC main
  storage when they contain no canonical semantic or recovery-only copy.
- PostgreSQL data and WAL, durable queue/outbox state contained in PostgreSQL,
  backups, snapshots, archive worktrees and exporter state, and model or
  embedding artifacts remain on the operator-controlled network-share mount
  with mount gating, snapshots, and checksumming as applicable.
- Services fail closed when the required mount is absent. Heavy or durable data
  must not silently spill onto LXC main storage.
- Credentials and key material retain ADR 0007's local root-controlled or
  external-key-facility boundary; they do not move onto the network share.

## Consequences

- Builders can implement one command engine without inferring transport-specific
  mutation behavior.
- Fine-grained scopes reduce the effect of a compromised client while the
  legacy broad scope remains usable for a bounded credential migration.
- Stale and retry failures are actionable without reflecting sensitive memory
  content into tool errors or logs.
- Hard-forget acceptance and verified cryptographic erasure are visibly
  different states.
- Four-attempt serializable retry behavior is deterministic enough to test and
  remains bounded under contention.
- Production GitHub ingress remains Milestone 6 work even though its adapter
  seam is fixed in Milestone 3.
- LXC-local application setup stays practical without weakening the durable
  storage boundary.
