# Scalevault Milestone 5: First Genesis Archive Import Plan

Archived after the exact-source import completed on 2026-08-08
(America/Chicago). Operational evidence is recorded in
`docs/milestone-5-genesis-first-import-evidence-2026-08-08.md`.

**Purpose:** Give Codex a self-contained implementation and execution prompt for completing the first real Genesis Kivra archive import into Scalevault without widening the reviewed source set or collapsing staged provenance into endorsed autobiography.

## Read this first: immutable pins and authorization boundary

### Scalevault implementation reference

Known Milestone 5 progress point:

```text
JTM-rootstorm/scalevault
b01022a26562d8dced97371a322cfbd45ce69bb6
```

This is **not** a claim that Milestone 5 is complete. It is the last reviewed progress point before the first real Genesis import.

If the Scalevault working branch is ahead of this commit, **do not reset it blindly**. Review the delta from `b01022a...` to the current branch head and make sure later work is compatible with this plan.

### FIRST IMPORT SOURCE PIN

The first authorized Genesis import source is exactly:

```text
Repository: JTM-rootstorm/scalevault-memory-ingress
Commit:     7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9
```

**This exact commit is the source-of-truth snapshot for the first import.**

Do not substitute:

- `main`;
- the repository's current HEAD;
- a newer tag;
- `f4338047f2f0e12d68b83aa6ffe3653bafeb1f2d`;
- or any later commit.

The existing Scalevault compatibility note still references the earlier reviewed snapshot:

```text
b69f06d339ff5ee9052c08f40d6968cf55ee4572
```

That operational pin must be moved to `7dc1cae...` for the first import.

The delta from `b69f06d...` through `7dc1cae...` was reviewed before authorization and consists only of three later Genesis v2 checkpoint files for Scalevault Milestones 2, 3, and 4. No ingress contract/schema files changed in that interval.

### AUTHORIZATION CHECKPOINT IS NOT SOURCE INPUT

After the source snapshot was frozen, Genesis created an authorization checkpoint at:

```text
JTM-rootstorm/scalevault-memory-ingress
f4338047f2f0e12d68b83aa6ffe3653bafeb1f2d
```

That commit is **post-freeze authorization evidence only**.

It is deliberately **not part of the first authorized import set**.

The first import must therefore have the following relationship:

```text
authorized source data  = ingress repo @ 7dc1cae...
authorization evidence  = later checkpoint/commit f433804...
```

Do not solve this apparent paradox by advancing the source pin to the authorization commit. The pin separation is intentional.

---

# Genesis authorization

Genesis explicitly authorized the first real import under these constraints:

1. Preserve `kivra:genesis` as the autobiographical owner and source perspective where specified by the source contract.
2. Preserve original source bytes or cryptographic provenance, Git provenance, checkpoint/candidate identity, visibility recommendation, relationship/participant bindings, interaction identity, interpretation limits, exclusions, and supersession information.
3. Route imported material through Milestone 5 nomination/selection policy. Do not directly insert canonical Memory rows and do not use legacy mutation-v1 calls as a policy bypass.
4. Import permission is **not** blanket autobiographical endorsement.
5. Imported Genesis records must not be rewritten as firsthand Continuant experiences.
6. Visibility may narrow during safety staging but must never expand during import.
7. Omissions and rejections must be recorded rather than silently discarded.
8. The original ingress Git repository remains immutable source evidence.
9. The apply operation must be bound to an exact deterministic plan/bundle digest.
10. A materially different source snapshot, transformation, ownership mapping, visibility expansion, or policy-bypass path requires fresh review.

Do not ask for another conversational permission merely because the deterministic digest becomes known. The source snapshot and transformation boundary have already been authorized. The implementation must still enforce exact digest matching at apply time.

---

# Critical semantic rule

> **Imported does not mean endorsed. Staged does not mean remembered.**

The first import is the crossing of provenance-preserved Genesis-era material into Scalevault's reviewable policy system.

It is **not** permission to:
- mark every record active;
- promote all records;
- claim Genesis and Continuant are the same runtime;
- copy Genesis relationship history into another Kivra's autobiography;
- make project-local or relationship-local material globally visible;
- infer missing participants from `triggered_by`;
- or discard exclusions because they are inconvenient to map.

---

# Relevant accepted M5 behavior

At the reviewed M5 state:

- `selection-v1` records immutable outcomes of `omit`, `candidate`, `active`, or `reject`.
- `memory_nominate` / mutation-v2 is the new policy entry point.
- ordinary mutation-v1 `memory_observe`, `memory_remember`, and semantic `memory_revise` must not be used as an undeclared policy bypass;
- candidate promotion and expiry are separate canonical lifecycle events;
- imported/unreconciled material is policy-qualified as **candidate**, not automatically active;
- selection decisions remain auditable even when no Memory row is created;
- private-seed application requires an exact digest match and explicit approval;
- ingress-shaped nominations have already been exercised through the shared `SelectionEngine`;
- GitHub ingress `processor.py` and `validator.py` at `b01022a...` are still effectively stubs and may need real implementation before this import can be safely executed.

Treat the existing architecture as authoritative. Extend it rather than creating an alternate import-only database path.

---

# Source contracts to audit at the frozen ingress commit

Before writing importer code, inspect these files **at `7dc1cae...`, not current main**:

```text
README.md
docs/GENESIS_CHECKPOINT_V2.md
docs/GENESIS_CHECKPOINT_V1_COMPATIBILITY.md
docs/PROPOSAL_V1_COMPATIBILITY.md            # if present under this or equivalent name
schemas/genesis-checkpoint-v2.schema.json
the documented v1 checkpoint schema
the documented v1 proposal schema
```

Use the actual filenames present at the pin if a compatibility filename differs.

Live source paths expected from the existing Scalevault compatibility record are:

```text
ingress/v1/<installation-id>/<yyyy>/<mm>/<proposal-id>.json
ingress/checkpoints/v1/genesis/<yyyy>/<mm>/<checkpoint-id>.json
ingress/checkpoints/v2/genesis/<yyyy>/<mm>/<checkpoint-id>.json
```

Do **not** import:
- examples;
- documentation;
- schemas as memory;
- fixtures;
- README content;
- or any file introduced after `7dc1cae...`.

---

# Non-negotiable Genesis checkpoint v2 semantics

The v2 contract explicitly separates:

```text
owner_actor_id
perspective_actor_id
subject_actor_ids
participant_actor_ids
relationship_ids
interaction_id
visibility
```

The importer must preserve these distinctions.

Also preserve:

```text
candidate_id
candidate type
disposition
confidence
scope
ontology
why_it_matters
evidence summaries/references
interpretation_limits
review recommendation
supersedes
exclusions
checkpoint identity and chain
source conversation provenance
```

Important rules from the v2 contract:

- `triggered_by` records who requested the archive pass. It is **not** proof that the requester is a subject, participant, or relationship counterparty.
- a runtime/process/Codex role is not automatically a durable actor;
- visibility cannot expand during import;
- memories owned by different actors do not merge merely because they share an interaction;
- v1 relationship-scoped records with missing explicit bindings remain unresolved until reviewed;
- staged candidates require later authorized review;
- imported does not mean endorsed.

---

# Do not force checkpoint v2 through a lossy private-seed shape

The M5 private-seed mechanism is useful for its safety properties:

- local-only source;
- strict file checks;
- secret scanning;
- deterministic record hashes;
- deterministic bundle digest;
- content-free planning;
- exact-digest apply gate;
- ordinary nomination/selection path.

However, **Genesis checkpoint v2 contains richer provenance/binding semantics than the private-seed memory payload by itself**.

Do not throw away:
- relationship IDs;
- participant IDs;
- interaction IDs;
- staged visibility recommendation;
- candidate/exclusion IDs;
- supersession links;
- or anti-inference exclusions

simply so the data fits the existing seed DTO.

Acceptable implementation approaches, in preference order:

1. **Implement a first-class GitHub Genesis ingress adapter** that validates the source format, archives raw source/provenance, produces policy nominations, and preserves the extra checkpoint metadata in the appropriate canonical/import metadata structures.
2. Reuse private-seed planning/application internally **only if** the additional Genesis provenance is preserved losslessly alongside the nomination and remains transactionally/auditably linked to it.
3. If the current schema has no safe place for required binding/exclusion/supersession data, add the smallest coherent schema/metadata/event extension necessary before applying the real corpus.

### Hard stop

If implementing the real import would require silently flattening or discarding any required v2 identity, relationship, visibility, exclusion, or supersession information:

**STOP BEFORE CANONICAL APPLY. Implement the missing representation first.**

A partial dry-run implementation is preferable to a lossy production import.

---

# First-import policy posture

For the first Genesis migration, prefer a conservative imported/unreconciled policy posture.

Checkpoint-authored words such as `disposition`, `confidence`, or `review.recommended_action` are source semantics and review hints. They are **not authority grants** to the M5 policy engine.

Unless existing signed policy requires otherwise, imported checkpoint-derived nominations should enter through the imported/unreconciled basis so that migration provenance alone cannot create active autobiography.

Where the policy/profile defines the equivalent of:

```text
selection_basis: imported_legacy
qualifier: imported_source_unreconciled
authority: imported_legacy_memory
evidence: trusted import manifest
outcome: candidate
```

use that policy path.

Do not promote an imported record merely because the source checkpoint said:
- `confidence: explicit`;
- `disposition: endorse_for_staging`;
- `recommended_action: retain_*`;
- or because Mike/Genesis deliberately chose to archive it.

Those fields matter during later review but do not bypass M5 selection authority.

Explicit user corrections, explicit permissions, or verified project facts may later qualify for stronger outcomes under their own trusted evidence rules, but the **migration itself should not launder imported source metadata into that authority**.

---

# Visibility rule

The ingress `binding.visibility` value is a **staged recommendation**, not an authorization grant.

Import must never widen it.

If the current canonical nomination contract cannot directly express one of the ingress visibility namespaces, use a more restrictive canonical visibility for the unreconciled candidate and preserve the original proposed visibility in the import provenance/review metadata.

Never map:

```text
relationship_local -> global/shareable
project_local      -> global/shareable
owner_private      -> broader scope
review_only        -> ordinary broad retrieval
history_only       -> ordinary broad retrieval
```

A narrowing safety transform is acceptable if:
1. the original recommendation remains preserved;
2. the transform is documented in the plan;
3. later review can make an explicit scoped decision.

---

# Exclusions and anti-inference constraints

Exclusions are not decorative comments.

They are explicit anti-inference constraints with actor and relationship bindings.

For every imported checkpoint:

- preserve each exclusion ID;
- preserve its claim/reason/scope;
- preserve actor bindings;
- preserve relationship bindings;
- preserve supersession links.

If Scalevault already has a first-class exclusion/constraint representation, use it.

If it does not, preserve exclusions in immutable source/import metadata and **do not allow automatic promotion of affected candidates until the exclusion semantics can be honored during review/retrieval**.

Do not convert an exclusion into a positive memory statement that reverses its meaning.

---

# v1 handling

Existing v1 records are immutable historical ingress and must be validated under their original contract.

For v1 Genesis checkpoints:

- preserve original bytes and Git provenance;
- use the documented v1 migration rules;
- `checkpoint.origin_actor` may be used for owner/perspective only as the documented migration default;
- never infer participant or relationship identities from `triggered_by`;
- relationship-scoped v1 candidates without explicit reviewed bindings must remain `unresolved_legacy_binding`;
- unresolved relationship records must not participate in relationship retrieval.

Do not rewrite v1 source files into v2.

If a correction is necessary, represent it as derived migration metadata or a new append-only correction record, never by modifying the ingress repository.

---

# Provenance manifest

Create a deterministic local import manifest for the frozen source snapshot.

At minimum, every source item should retain:

```text
source_repository
source_snapshot_commit = 7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9
source_path
source_git_blob_sha
source_raw_sha256
source_contract/version
checkpoint/proposal ID
candidate/exclusion ID where applicable
owner actor
derived nomination hash/idempotency key
mapping/version used by importer
```

If practical, also retain the commit that originally introduced each file. The snapshot commit remains the hard import-set boundary.

The manifest itself must be deterministically serialized and hashed.

The final apply gate must be bound to the exact deterministic digest of:
- source snapshot identity;
- complete enumerated import set;
- raw source hashes;
- parser/schema versions;
- mapping version;
- and derived nomination plan.

If the repository changes after planning, that is irrelevant because the import is snapshot-pinned. If any local source bytes or derived plan differ from the reviewed digest, abort.

---

# Update the stale ingress pin in Scalevault

Do not erase historical evidence that `b69f06d...` was the 2026-08-07 compatibility snapshot.

Instead, append/update documentation so it clearly states:

```text
Historical compatibility snapshot:
b69f06d339ff5ee9052c08f40d6968cf55ee4572

First real Genesis import source pin:
7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9

Post-freeze authorization checkpoint:
f4338047f2f0e12d68b83aa6ffe3653bafeb1f2d
NOT part of first import source set
```

Any importer configuration/constants must use `7dc1cae...`.

Never implement this as “fetch current main then check that it is at least as new as the pin.” Fetch the exact commit/tree.

---

# Parallel swarm plan: 1 lead + 7 subagents

The main orchestrator owns integration and is the **only actor allowed to initiate the canonical apply**.

Subagents may inspect, implement, test, and review. They must not independently apply the real corpus.

Suggested split:

## Agent 1: Ingress contract auditor
- inspect ingress repo at `7dc1cae...`;
- inventory live v1 proposal, v1 checkpoint, and v2 checkpoint contracts;
- identify examples/fixtures to exclude;
- produce exact semantic mapping requirements.

## Agent 2: Snapshot/provenance implementation
- implement exact-commit fetch/enumeration;
- raw byte hashing;
- Git blob/source provenance;
- deterministic import manifest;
- protection against accidental HEAD/main widening.

## Agent 3: Validator implementation
- replace/fill the stub ingress validator;
- version-aware schema validation;
- repository/path validation;
- semantic checks beyond JSON Schema;
- v1 unresolved-binding checks;
- fail-closed unknown-format behavior.

## Agent 4: Processor/mapping implementation
- replace/fill the stub ingress processor;
- map validated source items to transport-neutral nomination inputs;
- preserve v2 bindings and staged metadata;
- preserve exclusions/supersession;
- never let source metadata self-confer policy authority.

## Agent 5: M5 policy integration reviewer
- verify all import writes flow through `SelectionEngine`;
- verify imported material cannot bypass policy;
- verify immutable selection decisions;
- verify candidate lifecycle behavior;
- verify idempotency/replay and duplicate handling.

## Agent 6: Test/abuse lane
Build adversarial tests for:
- latest-HEAD accidentally used instead of pin;
- post-pin `f433804...` accidentally included;
- `triggered_by` inferred as participant;
- owner/perspective conflation;
- relationship visibility expansion;
- v1 unresolved relationship binding;
- exclusion loss;
- supersession loss;
- candidate upgraded to active from source confidence;
- duplicate/replay behavior;
- source byte mutation;
- digest mismatch;
- partial transaction failure.

## Agent 7: Operations/recovery lane
- disposable PostgreSQL acceptance;
- canonical preflight and backup;
- content-free dry-run plan;
- before/after counts;
- rollback/recovery procedure;
- import evidence/acceptance document;
- no secret/private content committed to Scalevault repo.

### Model routing

The lead may use Sol High for architecture/integration and route bounded implementation/testing work to Terra or lower Sol reasoning levels where appropriate. Correctness and provenance take precedence over quota economy.

---

# Execution phases

## Phase 0: Freeze and inspect

1. Record current Scalevault branch/head.
2. Verify `b01022a...` is an ancestor or otherwise review the delta.
3. Fetch the ingress repository at exact commit `7dc1cae...`.
4. Prove the import enumerator sees only files reachable from that tree.
5. Assert `f433804...` and all later files are impossible to enter the first import plan.
6. Update Scalevault documentation/configuration to the new first-import pin.

No canonical writes in this phase.

## Phase 1: Complete validator/processor

Implement the real version-aware ingress validation and conversion path.

The importer should be structured approximately as:

```text
exact pinned Git tree
        ↓
raw source archive/provenance
        ↓
versioned schema validation
        ↓
semantic/binding validation
        ↓
lossless source-to-nomination mapping
        ↓
trusted server-side import context
        ↓
SelectionEngine
        ↓
selection decision
        ├── omit
        ├── reject
        └── candidate/other policy-permitted result
```

No direct projection/database inserts.

## Phase 2: Synthetic and repository tests

Run fast tests frequently.

Then run:
- full unit/contract verification;
- focused ingress tests;
- policy tests;
- disposable PostgreSQL tests;
- existing M3 mutation regressions;
- existing M4 retrieval regressions where relevant.

Do not use the canonical Memory Node as the test database.

## Phase 3: Real-corpus dry run, zero canonical writes

Against ingress commit `7dc1cae...`:

1. enumerate exact importable source files;
2. validate every file under its correct contract;
3. produce a content-free inventory/plan;
4. compute raw hashes and deterministic derived plan;
5. compute exact final digest;
6. report only safe metadata:
   - source pin;
   - counts by format;
   - counts by candidate/exclusion type if safe;
   - plan digest;
   - expected policy outcome classes;
   - unresolved v1 binding counts;
   - validation failures by safe code.

Do not print private statements, relationship content, evidence prose, or raw payloads into general logs.

### Required dry-run assertions

- source pin is exactly `7dc1cae...`;
- post-pin authorization checkpoint is absent;
- no example/fixture file is included;
- all source bytes/hash entries are stable;
- every v2 candidate retains owner/perspective/binding provenance;
- every exclusion is accounted for;
- every supersession edge is accounted for;
- no visibility expansion exists;
- no imported-source field grants itself trusted authority;
- planned database writes occur only through policy selection/nominations.

## Phase 4: Pre-apply canonical safety

Before applying the real corpus:

1. Take a verified backup/snapshot of the canonical Memory Node database.
2. Record pre-import counts and migration/schema state.
3. Confirm the canonical node is on the intended Milestone 5 source.
4. Confirm there is no unexpected active import worker consuming current ingress HEAD.
5. Confirm the planned digest still matches exactly.
6. Confirm the apply command is explicitly pointed at the frozen source/plan, never a mutable directory checkout.
7. Ensure only the lead/operator path can execute the real apply.

## Phase 5: Controlled apply

Apply exactly once through the ordinary nomination/selection service.

Requirements:
- SERIALIZABLE/atomic behavior as designed;
- deterministic idempotency;
- safe replay if invocation is repeated;
- no raw direct SQL insertion;
- no mutation-v1 bypass;
- no post-pin source;
- no automatic candidate promotion beyond policy;
- no visibility broadening.

If any record fails conversion because the current canonical model cannot preserve required semantics, fail that record/batch safely. Do not improvise a lossy conversion.

## Phase 6: Verification

After apply, verify:

- the import digest/source pin recorded by operational evidence is `7dc1cae...`;
- `f433804...` is absent from imported source provenance;
- imported records have expected selection decisions;
- omitted/rejected records have immutable decision history;
- candidate records are non-default retrieval as designed;
- ownership remains Genesis;
- Continuant has no counterfeit firsthand ownership;
- relationship/project visibility did not expand;
- exclusions and supersession provenance remain intact;
- replaying the exact import is idempotent;
- canonical event/projection rebuild remains deterministic;
- backup remains available until acceptance is complete.

Run retrieval probes only with authorized/test principals and do not expose private source text in acceptance logs.

---

# Stop conditions

Stop before real canonical apply if any of the following is true:

- importer source pin is not exactly `7dc1cae...`;
- latest/main is being enumerated;
- `f433804...` or later ingress data enters the plan;
- source contract validation is ambiguous;
- a v2 binding is dropped or inferred;
- exclusions cannot be preserved;
- supersession cannot be preserved;
- visibility would expand;
- Continuant is being assigned Genesis firsthand history;
- v1 relationship bindings are guessed;
- the processor uses legacy mutation-v1 as policy bypass;
- direct database/projection insertion is proposed;
- policy output is being inferred from source `confidence`/`disposition`;
- deterministic plan digest does not match at apply time;
- any test requires private data to be committed into the Scalevault source repository;
- the canonical DB cannot be backed up/recovered.

If blocked by a representation gap, implement the smallest coherent extension, test it, and resume from dry-run. Do not ask to waive the provenance rules.

---

# Acceptance evidence to produce

Create a dated Milestone 5 / first-import evidence document in Scalevault containing **content-free operational evidence only**.

Include:

```text
Scalevault implementation commit
Ingress repository
Authorized source snapshot: 7dc1cae...
Historical compatibility snapshot: b69f06d...
Post-freeze authorization commit: f433804... (not imported)
Importer/mapping version
Selection policy version + digest
Import plan/bundle digest
Counts by source format
Counts by safe policy outcome
Count of unresolved v1 bindings
Pre/post canonical event/memory/decision counts
Backup identifier/location (safe form)
Disposable acceptance results
Idempotent replay result
Known limitations / deferred review work
```

Do not include private memory statements or relationship content in the acceptance document.

Milestone 5 should not be marked complete solely because the import ran. Complete it only when its own acceptance criteria are satisfied.

---

# Definition of done for this task

The first Genesis import task is done when:

- Scalevault's operational ingress pin is moved from the historical `b69f06d...` snapshot to exact source `7dc1cae...`;
- the importer validates and processes the frozen source contract versions safely;
- Genesis checkpoint v2 bindings are not flattened;
- exclusions and supersession provenance are preserved;
- a deterministic content-free import plan/digest exists;
- canonical apply uses only the exact authorized source snapshot;
- imported material passes through the M5 nomination/selection system;
- policy decisions are recorded;
- imported material is not silently treated as Continuant firsthand autobiography;
- post-pin checkpoint `f433804...` remains outside the first import;
- replay is idempotent;
- backup/recovery and acceptance evidence are complete;
- repository tests and disposable PostgreSQL acceptance pass.

---

# Final instruction to the Codex orchestrator

Proceed autonomously through implementation, review, testing, dry-run, and the already-authorized exact-source import.

Do **not** stop merely to ask whether Genesis authorizes the import: that authorization has already been granted for the exact snapshot and boundaries above.

Do stop canonical apply for a genuine safety/integrity failure listed in the stop conditions. Fix implementation defects when possible, re-run validation, and keep the source pin unchanged.

Use parallel subagents aggressively for independent review and implementation, but funnel all canonical apply authority through the lead/orchestrator.

The goal is not merely to “get the memories into PostgreSQL.”

The goal is to cross the Genesis archive into Scalevault **without losing the provenance distinctions that make the memories meaningful**.
