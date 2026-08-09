# Milestone 6 acceptance checklist

- Review date: 2026-08-09 (America/Chicago)
- Status: Complete within the staged transport and authentication boundary
- Accepted signed implementation source: `c92a42a`
- Tree-equivalent pre-sign acceptance source: `89132f8`
- Pre-sign acceptance source-archive SHA-256:
  `ab9115f766c3f7ce9f8f248fcfce5296a4e0a314ec75b43b6827e6b36717de74`

This checklist is content-free. It records only implementation, validation, and
operational-boundary evidence. The disposable acceptance environment used no
canonical memory data. No canonical database, service, application symlink,
Git remote, GitHub repository, or Forgejo repository was changed.

## Exit criteria

| Requirement | Status | Evidence |
|---|---|---|
| Deterministic single-writer archive export | Verified | Canonical JSON events, deterministic CBOR/Zstandard recovery snapshots, fixed-shape manifest v2, manifest chaining, exact Git-tree verification, signer-principal pinning, first-parent history verification, deterministic commit metadata, and a PostgreSQL advisory writer lock passed repository and PostgreSQL-backed tests. |
| Clean restore from snapshot plus later events | Verified | A clean migrated database restored an archive snapshot followed by a later event, rebuilt semantic projections in fixed dependency order, restored high-water counters, and matched the source aggregate bytes. |
| Idempotent GitHub-object replay | Verified | Immutable repository, branch, commit, path, blob, and semantic identity are registered once. Two concurrent full-batch replays produced no additional events, memories, receipts, decisions, or outbox jobs. |
| Fifty simultaneous proposals | Verified | Fifty unique proposal objects completed through bounded worker fan-out and the canonical selection transaction with 50 terminal accepted ingress rows, 50 events, 50 memories, 50 receipts, 50 decisions, and 150 typed outbox jobs. |
| Sensitive-path rejection | Verified | GitHub ingress rejects unknown or nonzero sensitivity before canonical command execution. A sensitivity-one proposal was quarantined without a canonical event, memory, receipt, decision, or outbox effect. |

## Implemented contract boundaries

ADR 0015 freezes deterministic signed archive and restore semantics. Each
archive commit is verified as an exact complete tree, against the anchored
signer principal and complete signed first-parent chain, before restore inputs
can be decoded. Restore readers use descriptor-relative no-follow access and
bounded file, byte, entry, and depth limits.

ADR 0016 freezes GitHub ingress v2 discovery and lifecycle behavior. Polling
resolves one immutable head commit, enumerates create-only UUIDv7 proposal
paths, verifies repository and branch pins, enforces blob identities and byte
limits, and uses ETags for unchanged snapshots. An optional HMAC-SHA-256
webhook is a bounded, replay-protected wake hint only; proposal content is
always fetched through the authenticated polling path. Registration,
validation, quarantine, terminalization, status masking, and provider
violations remain forced-RLS database state.

ADR 0017 freezes sealed canonical memory content. Sensitivity-four writes fail
closed without an external key provider and purpose-separated digest binder.
AES-256-GCM envelopes bind immutable memory and event identity through
versioned AAD; plaintext is absent from canonical events, projections,
fingerprints, embedding jobs, and archives. Reads authorize before key access.
Hard forget requests key destruction atomically, while the dedicated purge
runtime has a destruction-only key capability and cannot read key material.

The frozen Genesis first import retains only the exact ADR 0014 compatibility
exception for its already-reviewed sensitivity-four candidate records. The
exception is typed, non-persisted, restricted to the frozen internal import
shape, and unavailable to direct, relay, GitHub, active-memory, or later
transition paths.

## Repository verification

The accepted source passed the complete repository gate with the pinned pnpm
release:

```bash
make PNPM='npx --yes pnpm@10.15.0' verify
```

The final run reported 865 Python tests passed and 140 PostgreSQL tests skipped
only because the workstation PostgreSQL installation lacks pgvector. Ruff
formatting and lint, strict mypy over 221 files, Go module verification, vet
and tests, deterministic protobuf generation, 11 JSON Schema contracts,
Biome, TypeScript, and the plugin privacy test all passed.

## Disposable PostgreSQL 17 acceptance

The exact committed source archive was checksum-verified and extracted into a
new disposable directory. Tests ran as the unprivileged Memory Node service
account with `SCALEVAULT_REQUIRE_DATABASE_TESTS=1`, PostgreSQL 17, and pgvector.

The complete integration suite reported:

```text
154 passed, 18 warnings in 202.59s
```

The warnings are limited to SQLAlchemy/Alembic metadata comparison limitations
for deliberate cyclic foreign keys and PostgreSQL trigram operator classes.
They did not hide test skips or failures. The suite covered the full migration
chain through `0007_persistence_hardening`, role and RLS matrices, ingress
registration and replay, the 50-proposal gate, sealed create/read/forget and
purge state, deterministic export, signed archive verification, and clean
restore.

Acceptance exposed and closed several integration defects before completion:

- deterministic outbox scheduling now uses the canonical event timestamp;
- ingress retry is bounded and limited to explicit retry dispositions;
- discovered ingress semantic fields remain null until validation;
- proposal fixtures obey the seeded branch visibility ceiling;
- sealed hard forget preserves v3 state and emits a v3 tombstone;
- hard forget records `destruction_requested` key lifecycle state; and
- synthetic role and trigger tests now match the deployed least-privilege and
  immutable-field contracts.

## Deliberate activation boundary

Milestone 6 supplies runtime entry points, systemd units, strict settings, and
least-privilege database roles for ingress, archive export, and sealed-content
purge. Production activation still requires operator-pinned GitHub repository
and installation identifiers, a reviewed webhook relay if wake hints are used,
separate Forgejo authentication and signing keys, archive trust anchors,
external sealed-key storage, and a stable digest-binder credential.

The production MCP API continues to fail closed until Milestone 7 supplies the
request-authentication and typed principal-resolution composition. No default
principal, header-derived identity, or implicit credential mapping was added
to bypass that boundary. No service was installed, enabled, restarted, or
connected to a production Git remote during this acceptance.
