# ADR 0014: Pinned Genesis first-import contract

- Status: Accepted
- Date: 2026-08-08
- Supersedes: None
- Extends: ADR 0004, ADR 0005, ADR 0008, ADR 0009, ADR 0010, and ADR 0013

## Context

The first Genesis archive import crosses provenance-bearing, staged material
from the append-only GitHub ingress repository into ScaleVault's canonical
selection system. The ingress repository is transport evidence, not canonical
memory, policy authority, or proof of runtime identity continuity. In
particular, imported Genesis material must not become Continuant firsthand
autobiography merely because it was selected for archival review.

The authorized source set is the Git tree of exactly:

```text
repository: JTM-rootstorm/scalevault-memory-ingress
snapshot:   7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9
```

The historical compatibility snapshot is
`b69f06d339ff5ee9052c08f40d6968cf55ee4572`. The post-freeze authorization
commit is `f4338047f2f0e12d68b83aa6ffe3653bafeb1f2d`; it is not source input.
It is a direct descendant of the authorized snapshot and must remain outside
the first-import tree.

The source snapshot contains legacy proposal v1, Genesis checkpoint v1, and
Genesis checkpoint v2 records. Checkpoint v2 requires actor, relationship,
interaction, and visibility distinctions that private-seed payloads alone do
not represent. The importer therefore needs an explicit provenance model and
must use the ordinary nomination and selection boundary.

One checkpoint path in the authorized tree contains a bounded, known
schema-compatibility defect: it uses the raw values
`federation_shared_candidate` and `federation`, which are not enumerated by
the pinned v2 schema. Treating those values as generally valid would silently
widen the source contract; discarding the record would lose authorized source
evidence.

## Decision

### Exact source boundary

The Genesis first importer accepts only a detached, object-verified Git tree at
`7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9`. It enumerates tree entries, not a
mutable checkout, branch, tag, remote default, or current repository HEAD.

Only these anchored paths are eligible:

```text
ingress/v1/<installation-id>/<yyyy>/<mm>/<proposal-id>.json
ingress/checkpoints/v1/genesis/<yyyy>/<mm>/<checkpoint-id>.json
ingress/checkpoints/v2/genesis/<yyyy>/<mm>/<checkpoint-id>.json
```

The enumerator rejects an unknown ingress path, a path/version mismatch, a
non-regular file, duplicate identity, or a source item not reachable from the
pinned tree. It excludes documentation, schemas, examples, fixtures, README
content, and all post-pin objects. The implementation asserts that
`f433804...` is absent from the tree and is never an accepted source snapshot.

### Version-aware validation and a path-bound compatibility correction

Proposal v1 records validate with the proposal-v1 schema. Checkpoint v1
records validate under their documented v1 contract and are reported as
`legacy_supported`; they are never forced through the v2 schema or rewritten.
Checkpoint v2 records validate with the pinned v2 schema plus semantic actor,
relationship, visibility, and identity checks.

The sole exception is limited to compatibility version
`genesis-first-import-compat-v1` and this exact source identity tuple:

```text
snapshot: 7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9
path: ingress/checkpoints/v2/genesis/2026/08/genesis-checkpoint-20260807T124400-0500-4cb2fa62-a30e-4e46-a165-c24031dcce20.json
git blob object ID: 76214f303012d756c34a3b5bdf9948267a1418e3
raw SHA-256: f0f147d1ee8c748c7080ee821f1a48751b50d31c78912cbd3e1b358da39f83e7
checkpoint ID: genesis-checkpoint-20260807T124400-0500-4cb2fa62-a30e-4e46-a165-c24031dcce20
candidate ID: candidate-0b388348-39d8-46da-b78c-956dbe1e02e5
exclusion IDs: exclusion-dca9d34c-7b22-4ce2-885d-e3ba8f1c4f54
               exclusion-087d1403-46ed-43d3-93e2-14e5bbf3794c
```

For that source record only, the importer may recognize exactly these five raw
source pointers and values:

```text
/candidates/1/disposition = federation_shared_candidate
/candidates/1/scope = federation
/candidates/1/binding/visibility = federation_shared_candidate
/exclusions/0/scope = federation
/exclusions/1/scope = federation
```

The raw source bytes and raw field values remain immutable provenance; they are
not rewritten, coerced in place, or presented as schema-conformant source
values. No other path, commit, blob, hash, checkpoint, record, field, enum
spelling, pointer, or compatibility version receives this exception.

The affected candidate is mapped only to an imported/unreconciled,
review-only nomination with the conservative policy posture:

```text
selection_basis: imported_legacy
qualifier: imported_source_unreconciled
authority: imported_legacy_memory
required outcome: candidate
canonical effective visibility: private_root
```

Its raw scope, disposition, and visibility values remain source metadata for
later authorized review. The raw visibility marker is not a canonical
visibility value; it is retained as provenance while the canonical candidate is
restricted to `private_root`. The candidate cannot auto-promote. These raw
values do not grant federation visibility, stronger authority, active status,
or a general parser extension. The affected exclusions are preserved as
exclusions with their raw scope retained in source provenance; they must block
automatic promotion while their full semantics are not representable in review
and retrieval.

### Immutable import representation

The canonical model provides append-only, tenant-scoped representation for an
import run, every enumerated source record, candidate or proposal mapping,
exclusion, and supersession edge. It stores at least:

- source repository, pinned snapshot commit, path, Git blob object ID, raw
  SHA-256, source contract/version, and original introducing commit when
  available;
- checkpoint/proposal and candidate/exclusion identities; checkpoint chain,
  idempotency key, origin/runtime, trigger identity, and source-conversation
  provenance;
- owner, perspective, subject, participant, relationship, interaction, and
  original visibility bindings without conflation;
- original candidate type, disposition, confidence, scope, ontology, review
  recommendation, evidence references, interpretation limits, and all
  supersession links;
- compatibility-correction identity and raw values where the narrow exception
  applies; and
- deterministic mapping version, per-record nomination digest/idempotency key,
  complete content-free plan digest, selection decision, and nullable canonical
  event/memory references.

Planning is zero-write against the canonical database and does not archive raw
source bytes there. It produces only a protected local plan artifact and a
content-free manifest. Raw source bytes enter the protected import
archive/provenance store only during apply. General logs, plans, selection
history, and this repository's committed evidence remain content-free.

Once apply starts, an import run records the exact approved digest and evolves
only through append-only state transitions: `applying`, `completed`, or
`failed`. An interrupted run may resume only with the same snapshot, plan
digest, compatibility version, and deterministic per-record identities. A
resumed run processes only source records without a terminal linkage; records
with a terminal selection result replay that result. It cannot substitute a
new plan or alter already recorded source provenance. This permits bounded
per-record transactions without treating a partial run as a different import.

Exclusions are first-class anti-inference constraints, not positive memories or
free-text annotations. Their claim, reason, scope, actor and relationship
bindings, and supersession references remain linked to the source record.
Supersession is represented as directed provenance edges for both candidates
and exclusions, even when the initial import has none.

### Binding and identity rules

V2 owner, perspective, subject, participant, relationship, interaction, and
visibility fields answer distinct questions and are preserved separately.
Shared interaction IDs do not merge ownership or perspective. A runtime or
Codex role is not automatically a durable actor. `triggered_by` records an
archive request and never creates a subject, participant, author, or
relationship binding.

For v1 checkpoints only, owner and perspective may derive from
`checkpoint.origin_actor` as documented migration defaults. Relationship-scoped
or relationship-local v1 candidates remain `unresolved_legacy_binding` and are
excluded from ordinary relationship retrieval pending authorized explicit
bindings. Imported Genesis ownership remains Genesis provenance. No mapping
assigns Genesis-only events as firsthand Continuant experience.

Import may retain or narrow visibility only. It never expands relationship,
project, owner-private, review-only, or history-only material into a broader
retrieval scope. Source confidence, disposition, review recommendation, and
archival choice are review hints, not policy authority.

### Atomic policy linkage and importer authority

Each source-derived proposal or candidate enters the transport-neutral
`SelectionEngine` nomination boundary. The dedicated Genesis importer is the
only component authorized to apply this import plan. It operates with a
narrow, non-interactive import capability bound to the exact snapshot and plan
digest; relay, ordinary ingress, generic MCP callers, private seeds, and
mutation-v1 tools cannot obtain or emulate that capability.

For each record, selection outcome, command receipt, canonical
event/projection when one exists, immutable selection decision, protected
import-source archive/linkage, and relevant exclusion links commit atomically
in the same `SERIALIZABLE` transaction. An omit or reject still commits its
decision, receipt, and source linkage without a Memory row. Direct
SQL/projection writes and mutation-v1 are prohibited.

The importer uses deterministic per-record idempotency keys scoped to the
mapping version and source identity. Replaying the same accepted plan returns
the original terminal results; it does not create new canonical events,
decisions, or source records.

### Content-free planning, apply, and replay gates

Planning validates the exact source tree, captures a content-free provenance
catalog, builds all derived nominations, records omissions and exclusions, and emits a
deterministic content-free manifest. Its domain-separated digest covers the
repository identity, snapshot commit, complete enumerated path set, raw hashes,
Git blob IDs, parser/schema versions, compatibility-correction version,
mapping version, and derived nomination plan.

Apply requires an explicit operator approval bound to that exact digest and
uses the frozen plan, not a mutable directory. A source-byte, plan, parser,
mapping, or digest change aborts the operation. Before real apply, the
canonical database must have a verified backup, recorded pre-state, intended
schema/source revision, and no unexpected worker processing mutable ingress
HEAD. Afterward, acceptance evidence records only safe counts, source pin,
digest, policy profile identity, backup reference, and replay result.

## Stop conditions

Stop before canonical apply when any of the following occurs:

- source commit, tree, path, blob ID, raw hash, parser/schema version, mapping
  version, or plan digest differs from the approved plan;
- any source is selected from current HEAD/main, a mutable checkout, or a
  post-pin commit including `f433804...`;
- a path/version does not validate, an unknown compatibility value appears, or
  any narrow-exception identity element (snapshot, path, blob, raw hash,
  checkpoint, record, pointer, value, or compatibility version) does not
  match exactly;
- a binding, exclusion, supersession edge, source value, or visibility
  recommendation cannot be preserved without loss;
- v1 relationship bindings are guessed or unresolved candidates could enter
  relationship retrieval;
- imported source fields would grant effective authority, active status, or
  wider visibility;
- any write bypasses `SelectionEngine`, uses mutation-v1, or directly inserts
  a projection;
- the import cannot be made atomic, idempotent, backed up, and recoverable; or
- a test, log, plan, or committed artifact would expose private source content.

## Consequences

- The first import has a reproducible, content-free, tree-bounded audit trail
  while preserving protected raw provenance.
- The schema defect is handled honestly and narrowly rather than becoming an
  accidental new public source contract.
- Genesis bindings, exclusions, and relationship boundaries remain reviewable
  without converting staged archive material into endorsed autobiography.
- The additional immutable import and exclusion representation increases schema
  and migration work, but prevents provenance loss and policy bypasses.
