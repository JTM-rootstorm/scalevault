# Milestone 3 acceptance checklist

- Review date: 2026-08-08 (America/Chicago)
- Status: Complete
- Accepted implementation source: `d968546`

This checklist separates repository verification, the disposable PostgreSQL 17
and pgvector concurrency lane, and the canonical Memory Node deployment. The
canonical database was not used for disposable tests and received no synthetic
memory event.

## Task checklist

| Requirement | Status | Evidence |
|---|---|---|
| Eight direct mutation tools | Verified | The live MCP server advertises exactly `memory_observe`, `memory_remember`, `memory_revise`, `memory_link`, `memory_open_conflict`, `memory_resolve_conflict`, `memory_retire`, and `memory_forget`, with strict closed schemas and structured success/error envelopes. |
| Transport-neutral command engine | Verified | Direct, relay-shaped, and validated-ingress principals invoke the same `MutationEngine.execute` entry point. Provider discovery and proposal conversion remain outside the engine. |
| SERIALIZABLE retries and advisory locking | Verified | The transaction runner creates a fresh SERIALIZABLE transaction per attempt, retries only SQLSTATE `40001`, and preserves deterministic command identity. Storage wrappers preserve serialization failures instead of sanitizing them prematurely. |
| Idempotency and expected revisions | Verified | Twenty concurrent identical calls produced one event, projection, receipt, and logical outbox set with nineteen receipt replays. Sixteen same-revision updates produced one revision-2 winner and fifteen structured stale responses. Reusing a key for different material produced `idempotency_key_reused` without additional writes. |
| Atomic projections and outbox | Verified | Event, live projection, receipt, ingress result, and IDs-only outbox jobs commit in one transaction. An injected outbox failure rolled all of them back. |
| Conflict and lifecycle mutations | Verified | Link, open conflict, resolve conflict, retire, logical forget, and hard-forget staging passed against PostgreSQL. Disputed memories must resolve their conflict before retire or forget. |
| Structured privacy-safe MCP failures | Verified | Strict JSON types and canonical lowercase UUIDv7 inputs are enforced before SDK coercion. Malformed inputs and executor failures return bounded structured errors without reflecting statements, metadata, SQL, or exception text. |
| Least-privilege API projection writes | Verified | The API role has SELECT, INSERT, and UPDATE only on memories, links, conflicts, and conflict members for the atomic mutation transaction. It has no delete, evidence-mutation, content-key-mutation, DDL, or bypass privileges. |

## Repository verification

The accepted source passed the complete repository gate with the pinned pnpm
10.15.0 toolchain invoked through `npx`:

```bash
make PNPM='npx --yes pnpm@10.15.0' verify
```

The final run reported 372 Python tests passed and 62 PostgreSQL integration
tests skipped only because the workstation PostgreSQL installation lacks
pgvector. Ruff formatting and lint, strict mypy over 92 files, Go module
verification, vet and tests, deterministic Go builds, protobuf generation,
JSON Schema validation, TypeScript, Biome, and the plugin privacy test all
passed.

## Disposable PostgreSQL 17 acceptance

The authoritative mutation lane ran as `postgres` with
`SCALEVAULT_REQUIRE_DATABASE_TESTS=1`, PostgreSQL 17.10, and pgvector 0.8.0.
Application source and the locked test virtual environment were staged on the
LXC main disk under:

```text
/opt/scalevault-m3-acceptance-20260808
```

Disposable PostgreSQL clusters and test logs remained on the controlled mount
under:

```text
/mnt/memory/scalevault-m3-acceptance-20260808
```

The first run correctly failed five of seven cases. A live diagnostic found
that mutation jobs used the outbox reference name `memory_revision`, while the
privacy allowlist accepts only IDs, versions, and sequences. The ingress fixture
also attempted to insert directly at `validated`, which the lifecycle trigger
correctly rejected. Commit `d968546` renamed only the outbox reference to
`memory_version`, added exact payload assertions, and made the fixture perform
`discovered` to `validated`.

The corrected committed source passed all seven required cases without skips in
477.93 seconds. Coverage included:

- sixteen concurrent revisions with one winner and no lost update;
- twenty concurrent identical idempotent calls with exactly one canonical event;
- cross-client exact-fingerprint serialization;
- atomic rollback after injected outbox failure;
- direct and validated-ingress atomic processing plus receipt replay;
- every non-create mutation and hard-forget outbox staging; and
- sealed-branch fail-closed behavior with no partial writes.

The final JUnit record is retained at:

```text
/mnt/memory/scalevault-m3-acceptance-20260808/logs/mutation-tests-r2.xml
```

## Canonical Memory Node deployment

The accepted release is installed under:

```text
/opt/kivra-memory/releases/d968546
```

The `/opt/kivra-memory/app` symlink was atomically switched from the retained
Milestone 2 release `7679f25`. The idempotent PostgreSQL role bootstrap applied
the reviewed projection grants before cutover. API and tunnel restart, loopback
health, database/migration/extension readiness, and exact eight-tool MCP
discovery all passed. PostgreSQL data remained under:

```text
/mnt/memory/kivra-memory/postgresql/17/main
```

API, tunnel, and node-agent remain disabled at boot. PostgreSQL, API, and tunnel
were active after validation; node-agent remained inactive.

## Deliberate operational boundary

Milestone 3 completes and validates the mutation schemas, adapters, transaction
engine, concurrency behavior, and synthetic external-ingress seam. Production
request authentication and request-scoped `CommandPrincipal` resolution belong
to Milestone 7. Until then, the default live mutation executor fails closed with
structured `dependency_unavailable`.

A synthetic live MCP canary confirmed that boundary after cutover. The canonical
`memory_events` count was zero before and after the call. This milestone does not
claim production-authenticated writes, GitHub proposal conversion, read tools,
or Codex credential readiness.
