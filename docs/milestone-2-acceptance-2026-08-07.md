# Milestone 2 acceptance checklist

- Review date: 2026-08-07 (America/Chicago)
- Status: Complete
- Accepted implementation source: `7679f25`

This checklist separates repository and workstation evidence, the disposable
PostgreSQL 17 acceptance lane, and the canonical Debian Memory Node cutover.
The canonical database was not used for disposable tests.

## Task checklist

| Requirement | Status | Evidence |
|---|---|---|
| Identity, installation, ingress, lineage, subject, event, projection, evidence, link, conflict, embedding registry, outbox, and export checkpoint schema | Verified | The initial Alembic revision and SQLAlchemy metadata agree on 27 domain tables. Tenant and lineage foreign keys, bounded values, immutable fields, and forced row-level security passed integration tests. |
| Closed domain values and invalid-combination barriers | Verified | Shared enums and PostgreSQL constraints reject invalid scope, visibility, ontology, branch-ceiling, subject/session, and transport combinations. |
| UUIDv7 identifiers and canonical payload hashes | Verified | Property and database tests cover UUIDv7 generation, RFC 8785 canonical JSON, SHA-256 encoding, and rejection when canonical bytes do not decode to the stored JSON value. |
| Atomic event insertion | Verified | Tests cover counter serialization, reusable rolled-back sequences, installation and binding authority, and atomic acceptance of validated GitHub proposals with their result event. |
| Event replay and projection rebuild | Verified | Replay verified immutable events before rebuilding branch, memory, evidence, link, and conflict projections, then matched canonical aggregate bytes loaded from PostgreSQL. |
| Deterministic synthetic seed | Verified | The fixture contains one synthetic tenant, persona, lineage, root branch, global subject, direct client, relay client, GitHub ingress client, installation, and transport bindings. Dependency layers are flushed explicitly. |
| Runtime ownership and least privilege | Verified | The idempotent role bootstrap defines a non-login owner plus migrator, API, worker, ingress, and exporter roles; removes inherited public grants; preserves the API credential; and passed the role matrix against PostgreSQL. |
| Evolved GitHub ingress boundary | Recorded; implementation deferred | The private ingress repository is treated as a separately versioned input contract. The latest audited snapshot is pinned in `docs/ingress-compatibility.md`; no private checkpoint payload was imported during Milestone 2, and the importer remains Milestone 6 work. |

## Workstation verification

The implementation source at `7679f25` passed the complete repository gate with
the pinned pnpm 10.15.0 toolchain invoked through `npx` because pnpm was not
installed globally:

```bash
make PNPM='npx --yes pnpm@10.15.0' verify
```

The run reported 266 Python tests passed and 50 PostgreSQL integration tests
skipped only because the workstation PostgreSQL installation lacks pgvector.
Ruff, strict mypy, Go module verification, vet, tests, deterministic protobuf
generation, JSON Schema validation, TypeScript checking, Biome, and the plugin
privacy test all passed.

## Disposable PostgreSQL 17 acceptance

The authoritative lane ran as `postgres` from the exact implementation commit
with `SCALEVAULT_REQUIRE_DATABASE_TESTS=1` and PostgreSQL binaries from
`/usr/lib/postgresql/17/bin`. Its source, locked virtual environment, cache,
temporary clusters, and logs were all under:

```text
/mnt/memory/scalevault-m2-acceptance-20260807
```

PostgreSQL 17.10 with citext 1.6, pg_trgm 1.6, pgcrypto 1.3, and vector 0.8.0
passed all 62 integration cases without skips: 10 replay/migration, 24 role, 16
security, and 12 structure/readiness tests. Per-test clusters retained full
isolation; the lanes were capped at two concurrent shards to remain below the
NFS metadata startup timeout.

An earlier non-authoritative launch rejected a relative `TMPDIR` and fell back
to the LXC root filesystem. It was stopped immediately; the exact disposable
cluster directory was deleted and a subsequent scan found no matching
`/tmp/scalevault-postgres-*` directory. Only the absolute-path run is accepted
as release evidence.

## Canonical Memory Node cutover

Before the maintenance window, the live audit found the canonical database
owned by the Milestone 1 API role with no application tables, no Alembic
revision, and none of the four required extensions installed. A custom-format
dump, SHA-256 checksum, and `pg_restore --list` manifest were created under the
mounted PostgreSQL backup directory before API and tunnel were stopped.

The empty Milestone 1 database was also found to use `SQL_ASCII`, which makes
text results bytes in psycopg and prevents SQLAlchemy initialization. With the
validated dump retained and zero application tables confirmed, only the
`kivra_memory` database was recreated as UTF-8. Cluster roles and the existing
API password were preserved. The four extensions were installed, the role
bootstrap ran before and after Alembic, and the guarded migration reached
`0001_initial_domain`.

The canonical PostgreSQL data directory remained:

```text
/mnt/memory/kivra-memory/postgresql/17/main
```

Post-cutover catalog checks reported 28 public tables including Alembic's
ledger, 25 tenant tables with forced RLS, and a single application object owner
of `kivra_memory_owner`. API readiness reported database, migrations, and
extensions `ok`; tunnel readiness returned `ready`. The accepted release is
active under `/opt/kivra-memory/app`, and the prior M1 app tree is retained for
rollback. API, tunnel, and node-agent remain disabled at boot; the node-agent
also remains inactive. No credential value is recorded here.

## Storage and recovery boundary

All local canonical database files, local backups, and disposable acceptance
data remain on the `/mnt/memory` mount. The operator controls the hardware and
service boundary and reports that encrypted backups are sent to Backblaze. This
milestone records the local pre-cutover dump and validation separately; it does
not claim to have tested the external backup provider from inside the LXC.
