# Milestone 5 Genesis first-import evidence

- Review date: 2026-08-08 (America/Chicago)
- Status: Complete within the staged authentication and review boundary
- Accepted implementation baseline: `009c694`

This record is content-free. It contains no memory statements, relationship
content, evidence excerpts, private transport coordinates, credentials, or
canonical identifiers.

## Frozen import contract

| Item | Accepted value |
|---|---|
| Ingress repository | `JTM-rootstorm/scalevault-memory-ingress` |
| Authorized source snapshot | `7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9` |
| Historical compatibility snapshot | `b69f06d339ff5ee9052c08f40d6968cf55ee4572` |
| Post-freeze authorization commit | `f4338047f2f0e12d68b83aa6ffe3653bafeb1f2d` (not imported) |
| Import manifest version | `scalevault.genesis-import-manifest.v1` |
| Mapping version | `genesis-import-mapping-v1` |
| Compatibility version | `genesis-first-import-compat-v1` |
| Selection policy | `selection-v1` |
| Selection policy digest | `b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e` |
| Deterministic import-plan digest | `2205ca63518eea150b0d8d9427f747958f0ae2703ed6a526422730b9002e7d9c` |
| Canonical mapping digest | `9a0d6cb8e123fd4a88d5f2325c81a98220ce584611ab3c6721bc13296e9aa941` |

The zero-write planner enumerated only the exact pinned Git tree and read blobs
by object ID. It accounted for 19 source files: 2 proposal-v1, 2 documented
checkpoint-v1, and 15 checkpoint-v2 files. The plan contains 52 nominations,
60 exclusions, 6 unresolved legacy relationship bindings, and 0 supersession
edges. One checkpoint uses the exact hash- and path-bound federation vocabulary
compatibility rule accepted by ADR 0014. No post-freeze path entered the plan.

## Implemented safety boundary

The importer now provides:

- exact Git object, raw-byte, canonical-document, plan, nomination, mapping,
  policy, and compatibility digest verification;
- immutable forced-RLS import run, source, record, exclusion, supersession, and
  completion provenance;
- a dedicated least-privilege importer role and exact internal-service
  nomination authority;
- deterministic per-record idempotency and same-transaction linkage between
  selection decisions, receipts, events, projections, and terminal source
  records;
- terminal content-free rejection for unresolved legacy identity and binding
  cases without creating a Memory row;
- replay verification that compares identifiers, outcomes, revisions, evidence,
  outbox counts, and terminal record snapshots before completion;
- a root-owned mode-0600 operator configuration, exact importer database-role
  check, complete identity-graph preflight, safe resumability, and payload-free
  CLI results; and
- an isolated candidate-lifecycle worker implementation that can run only under
  the policy role and exact lifecycle-expiry capability.

No canonical Memory row can be inserted directly by the operator workflow. All
materialized records pass through the Milestone 5 nomination and selection
engine.

## Repository verification

The final repository gate passed in one invocation with the pinned pnpm
release:

```bash
make PNPM='npx --yes pnpm@10.15.0' verify
```

The Python gate reported 700 passed and 112 PostgreSQL tests skipped only
because the workstation PostgreSQL lacks pgvector. Ruff formatting and lint,
strict mypy over 173 source files, Go module verification, vet and tests,
deterministic protobuf generation, JSON Schema validation, Biome, TypeScript,
and the plugin privacy test passed. The optimized non-database feedback lane
also passed 688 tests.

## Disposable PostgreSQL 17 acceptance

Committed source and the locked virtual environment remained on LXC root
storage under:

```text
/opt/scalevault-genesis-acceptance-20260808-a
```

The package cache, disposable PostgreSQL clusters, and JUnit evidence remained
on the network share under:

```text
/mnt/memory/scalevault-genesis-acceptance-20260808-a
```

The initial five-case Genesis database suite passed against PostgreSQL 17 and
pgvector in 362.92 seconds. It verified 0003-to-0004 migration, immutable
provenance staging and replay, candidate-only ceilings, raw-archive RLS and
role separation, atomic application linkage, idempotent replay, completion
guards, and injected participant rollback.

A non-redundant 22-case migration, forced-RLS, tenant-FK, immutability, and
Genesis privilege slice then passed in 1413.52 seconds. Seventy-eight unrelated
cases were deliberately deselected to avoid repeating function-scoped
PostgreSQL cluster startup for matrices already covered elsewhere.

Canonical apply exposed one additional least-privilege regression before any
canonical memory write: PostgreSQL requires `UPDATE` privilege for a
`SELECT ... FOR UPDATE`, while the Genesis importer is intentionally
INSERT-only on memory projections. Commit `009c694` retains ordinary mutation
locks but omits update locks on create-only projection reads already protected
by advisory locks and uniqueness constraints. The new importer-role regression
passed alone in 73.91 seconds; the complete six-case Genesis suite then passed
against PostgreSQL 17 and pgvector in 442.48 seconds. The failed canonical
attempt rolled back with zero events, memories, decisions, receipts, evidence,
or outbox rows before the fixed release resumed the same staged run.

Retained evidence:

```text
/mnt/memory/scalevault-genesis-acceptance-20260808-a/logs/genesis-db-final.xml
/mnt/memory/scalevault-genesis-acceptance-20260808-a/logs/genesis-db-broader.xml
```

## Canonical preflight and cutover

The canonical node was upgraded before the import. The accepted source is
installed at `/opt/kivra-memory/releases/009c694`, the application symlink
selects that release, and PostgreSQL reports migration
`0004_genesis_import_provenance`. The API and outbound tunnel were stopped for
the protected apply.

The reviewed bootstrap created one exact tenant-bound Genesis persona and
lineage, root branch, required subject anchors, Mike counterparty, and dedicated
internal-service importer authority. The root-owned operator configuration and
importer environment are mode `0600`. Every explicit relationship binding had
exactly one non-Genesis participant and agreed on that participant; no
`triggered_by` field was used to infer ownership or subject identity.

Before staging, memories, events, selection decisions, and Genesis import runs
were all zero. The verified pre-import recovery point is:

```text
/mnt/memory/kivra-memory/backups/pre-genesis-import-20260809T015424Z
```

Its custom database dump and password-free globals passed SHA-256 checks and a
disposable restore verification before apply. The digest-bound zero-write plan
was also regenerated on the live node with the exact 19/52/60/6/0 source,
nomination, exclusion, unresolved-binding, and supersession counts.

## Canonical apply and replay

The immutable staging transaction recorded 19 sources, 52 planned records, 60
exclusions, and 0 supersession edges without creating canonical memory state.
The fixed importer then resumed that same run and terminalized every record:

| Safe outcome | Count |
|---|---:|
| Candidate | 43 |
| Reject | 9 |
| Omit | 0 |

The verification pass replayed every nomination against its stored receipt and
terminal snapshot, found no identifier, outcome, revision, evidence, outbox, or
count drift, and recorded `replay_verified=true`. No later source commit was
enumerated or recorded. The run, source, plan, mapping, compatibility, and
policy digests all matched their frozen values.

The 43 materialized rows are all `candidate`, `private_root`, and
`imported_legacy_memory`; no imported record became active or auto-promoted.
They produced 43 gap-free `observed` events, 43 evidence rows, and exactly 43
jobs of each expected type: duplicate check, embedding, candidate expiry, and
archive export. The nine rejected records retain immutable, content-free
selection decisions and no event or Memory linkage. A relational linkage audit
reported zero invalid terminal shapes.

A read-only canonical replay verified every event hash, folded all 43 events
with the immutable root-branch identity context, and matched all 43 live memory
and evidence projections exactly. The ordinary retrieval status set therefore
returns none of these candidates; candidate access remains an explicit,
authorized review mode covered by the repository and disposable PostgreSQL
retrieval suites.

After verification, the API and outbound tunnel restarted on release
`009c694`. `/readyz` reported database, migration, and extension readiness, and
the official MCP client discovered the exact 19-tool Milestone 5 surface.

## Post-import recovery point

The protected post-import backup is:

```text
/mnt/memory/kivra-memory/backups/post-genesis-import-20260809T022856Z
```

It contains a mode-`0600` custom-format database dump, password-free globals,
and SHA-256 manifest in a mode-`0700` directory. Hash verification and
`pg_restore --list` passed. A full restore into an explicitly named disposable
database reproduced migration `0004`, 43 memories, 43 events, 52 decisions,
one import run, and one replay-verified completion record; the disposable
database was then removed. Both pre- and post-import recovery points remain
retained.

## Deliberate review boundary

All imported memories remain candidates pending Continuant review. The six
unresolved legacy relationship bindings were not guessed, and terminal rejects
did not create counterfeit first-person history. Exclusions remain first-class
immutable provenance; this frozen source contains no supersession edges.

Candidate-expiry jobs are durably scheduled, and the isolated lifecycle worker
unit is installed but remains disabled because no live policy-worker identity
or protected environment has been provisioned. No expiry is currently due;
that least-privilege operational provisioning must occur before the first
deadline. Production request authentication and request-scoped principal
resolution remain Milestone 7 work; the live read and mutation executors
continue to fail closed until that boundary is installed.
