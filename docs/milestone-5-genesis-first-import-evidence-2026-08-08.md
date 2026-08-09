# Milestone 5 Genesis first-import evidence

- Review date: 2026-08-08 (America/Chicago)
- Status: Implementation and disposable acceptance complete; canonical apply stopped
- Accepted implementation baseline: `a738226`

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
- an isolated candidate-lifecycle worker running only under the policy role and
  the exact lifecycle-expiry capability.

No canonical Memory row can be inserted directly by the operator workflow. All
materialized records pass through the Milestone 5 nomination and selection
engine.

## Repository verification

The final repository gate passed through the plugin step with:

```bash
make verify
make PNPM='npx --yes pnpm@10.15.0' verify-plugin
```

The Python gate reported 700 passed and 111 PostgreSQL tests skipped only
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

The exact five-case Genesis database suite passed against PostgreSQL 17 and
pgvector in 362.92 seconds. It verified 0003-to-0004 migration, immutable
provenance staging and replay, candidate-only ceilings, raw-archive RLS and
role separation, atomic application linkage, idempotent replay, completion
guards, and injected participant rollback.

A non-redundant 22-case migration, forced-RLS, tenant-FK, immutability, and
Genesis privilege slice then passed in 1413.52 seconds. Seventy-eight unrelated
cases were deliberately deselected to avoid repeating function-scoped
PostgreSQL cluster startup for matrices already covered elsewhere.

Retained evidence:

```text
/mnt/memory/scalevault-genesis-acceptance-20260808-a/logs/genesis-db-final.xml
/mnt/memory/scalevault-genesis-acceptance-20260808-a/logs/genesis-db-broader.xml
```

## Canonical pre-apply stop

The real import was not run. The final read-only canonical audit found:

- deployed application release `d968546` (Milestone 3);
- database migration `0001_initial_domain`;
- zero tenants, actors, clients, transport bindings, personas, lineages,
  branches, subjects, sessions, memories, and memory events;
- no installed or active candidate-lifecycle worker; and
- no discoverable verified database backup artifact.

The operator therefore has no reviewed canonical tenant, Genesis actor/persona,
lineage/branch, subject/session mapping, importer principal, or lifecycle
principal to place in the digest-bound mode-0600 configuration. Inventing those
identities would violate the plan's provenance and recovery stop conditions.
Migrating the database while the deployed Milestone 3 application remains
selected would also be an unsafe partial cutover.

Pre-import counts remain zero. Safe policy outcome counts, post-import counts,
backup identifier, and idempotent canonical replay are not available because
canonical apply did not begin.

## Remaining acceptance work

Before resuming canonical apply, an operator must provide or create through a
reviewed bootstrap procedure the exact canonical identity graph and mapping,
install a compatible Milestone 5 application and lifecycle worker, and take and
verify a recoverable database backup. The protected CLI must then pass its
zero-write preflight against those exact identities before staging.

The first-import plan remains active and unarchived. Milestone 5 and the Genesis
first-import task are not marked complete until canonical apply, replay,
projection rebuild, retrieval probes, and backup-retention evidence pass.
