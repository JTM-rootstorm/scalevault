# Milestone 4 acceptance checklist

- Review date: 2026-08-08 (America/Chicago)
- Status: Complete within the staged authentication boundary
- Accepted implementation source: `071a8e6`

This checklist separates repository verification, disposable PostgreSQL 17 and
pgvector acceptance, the local embedding artifact, and the canonical Memory
Node deployment. Disposable tests used no canonical memory data. The canonical
application symlink, database, and service enablement were not changed.

## Task checklist

| Requirement | Status | Evidence |
|---|---|---|
| Lexical, trigram, filtered, and vector retrieval | Verified | Exact-branch, tenant, lineage, subject, scope, visibility, sensitivity, lifecycle, and validity filters execute before ranking. Committed memories are lexically searchable before an embedding exists. PostgreSQL full-text, trigram, and fixed-dimension cosine-vector paths passed against PostgreSQL 17 and pgvector. |
| Versioned embedding registry and worker | Verified | `memory_embeddings_v1`, the reviewed registry lifecycle, IDs-only outbox jobs, fenced `SKIP LOCKED` leasing, stale-revision rejection, idempotent replacement, tombstone cleanup, and the pinned CPU-only ONNX runtime passed. |
| Deterministic ranking and context budgeting | Verified | The checked-in `rrf-v1` profile, canonical profile digest, authority and recency modifiers, stable UUID tie-break, conflict grouping, UTF-8 upper-bound budgeting, explanation components, and output byte ceiling passed unit, contract, and evaluation fixtures. |
| Scope and privacy safety | Verified | Retrieval scope can only narrow server-derived authority. Cross-tenant, lineage, branch, project, session, visibility, sensitivity, and terminal-state canaries remain excluded. Hidden conflict members are not partially disclosed. |
| Conflict-aware results | Verified | Selecting either visible side expands the complete eligible open conflict as an atomic labelled group; an ineligible member suppresses the group. |
| Ingress and transport status | Verified | The two status tools return allowlisted coarse fields only. Repository paths, commit and blob identifiers, relay coordinates, certificate fingerprints, credentials, diagnostics, and payload material are absent. Unauthorized and missing ingress IDs are indistinguishable. |
| MCP read contract | Verified | Nine strict read/status tools precede the eight mutation tools, use closed schemas, enforce canonical UUIDv7 and strict JSON input, sanitize failures, annotate read-only behavior, and reject oversized responses. |

Milestone 4 deliberately uses exact requested-branch reads. Copy-on-write branch
ancestry is Milestone 11 scope and is not approximated by exposing mutable
ancestor projections.

## Repository verification

The accepted source passed the complete repository gate:

```bash
make PNPM='npx --yes pnpm@10.15.0' verify
```

The final run reported 474 Python tests passed and 72 database tests skipped
only because the workstation PostgreSQL installation lacks pgvector. Ruff
formatting and lint, strict mypy over 126 files, Go module verification, vet and
tests, deterministic protobuf generation, JSON Schema validation, TypeScript,
Biome, and the plugin privacy test all passed.

## Disposable PostgreSQL 17 acceptance

The authoritative database lane ran as `postgres` with
`SCALEVAULT_REQUIRE_DATABASE_TESTS=1`, PostgreSQL 17.10, and pgvector. Source and
the 333 MiB locked virtual environment remained on the LXC main disk under the
pre-sign staging identifier:

```text
/opt/kivra-memory/releases/43f1f68-m4
/opt/kivra-memory/releases/687e5e2f382a-m4/.venv
```

The staged source tree is byte-identical to signed implementation commit
`071a8e6`; signing changed commit identity after live acceptance without
changing its tree.

Disposable cluster data, model downloads, and retained JUnit evidence remained
on the network share under:

```text
/mnt/memory/scalevault-m4-acceptance-20260808
```

The first 48-case migration, privilege, retrieval, status, and worker run
passed 47 cases and exposed a real query-boundary defect: the pgvector adapter
requires a list or NumPy array, while the storage repository bound an immutable
tuple. Commit `6cec223` converts only the database-bound value and adds a
regression. A later assertion was corrected in `04eba2e` to distinguish an
eligible nearest neighbor with zero cosine similarity from a stale vector.

The corrected embedding lifecycle passed in 67.98 seconds. The remaining three
Milestone 4 database cases passed again against the latest source in 198.51
seconds. Seven mutation concurrency and lifecycle regressions also passed in
466.77 seconds, verifying that expanded embedding-job scheduling did not break
idempotency, atomicity, ingress reuse, conflict operations, or forget behavior.

Retained evidence:

```text
/mnt/memory/scalevault-m4-acceptance-20260808/logs/m4-focused-db.xml
/mnt/memory/scalevault-m4-acceptance-20260808/logs/m4-embedding-worker-final.xml
/mnt/memory/scalevault-m4-acceptance-20260808/logs/m4-focused-latest.xml
/mnt/memory/scalevault-m4-acceptance-20260808/logs/m4-mutation-regression.xml
```

The disposable temporary directory was empty after teardown and returned to
mode `0755`.

## Pinned local embedding artifact

The reviewed `sentence-transformers/all-MiniLM-L6-v2` ONNX graph, tokenizer,
and configuration were downloaded at the frozen upstream revision. The
official Apache-2.0 license text was retained alongside them. The operator-only
preparation step created the immutable bundle:

```text
/mnt/memory/kivra-memory/models/5f459ae8aa373980a780ecb390d25d8d583d812d1ee12951ae3569e3b9653441
```

The 87 MiB bundle is owned by `memory-worker`, its directory is non-writable,
and every artifact and manifest is mode `0440`. The worker verified all hashes,
loaded ONNX Runtime 1.28.0 with only `CPUExecutionProvider`, and embedded the
same synthetic statement twice. It produced a 384-dimensional vector with norm
`0.9999999660636719`, maximum repeat delta `0.0`, and no truncation. The live
NFS run also exposed and fixed an unconditional redundant `chown`; commit
`071a8e6` now preserves an already inherited group without asking a
root-squashed share to change ownership.

Runtime evidence is retained at:

```text
/mnt/memory/scalevault-m4-acceptance-20260808/logs/m4-model-runtime.txt
```

A transient unit copy pointing at the staged release passed
`systemd-analyze verify`. The worker unit was not installed, enabled, or
started against the canonical database.

## Deliberate operational boundary

Milestone 4 completes the read contracts, transport-neutral query and status
engines, hybrid storage, asynchronous worker, deterministic ranking, privacy
filters, and injectable MCP adapters. Production request authentication and
request-scoped principal resolution remain Milestone 7 scope. The default live
read and mutation executors therefore continue to fail closed with structured
`dependency_unavailable` responses.

No canonical database migration, synthetic canonical memory, application
symlink switch, service restart, or service enablement was performed for this
milestone. The accepted repository commits were signed and pushed only after
live validation completed.
