# Milestone 7 acceptance checklist

- Review date: 2026-08-09 (America/Chicago)
- Status: Complete for authenticated direct-private Codex access
- Deployed implementation source: `8b01b22`
- Deployed source-archive SHA-256:
  `f9bbcc33e7dcd7a1f99a823702ba6996006746fb67e7aae0db85f2c23e01f568`

This checklist is content-free. It records implementation, validation, and
operational evidence without memory statements, evidence values, bearer
tokens, verifier material, private hostnames, or database connection secrets.

## Exit criteria

| Requirement | Status | Evidence |
|---|---|---|
| Two Codex clients write different subjects concurrently | Verified | PostgreSQL-backed acceptance authenticated two independently provisioned clients, submitted concurrent nominations for different subjects, and verified distinct actor, client, credential, and transport-binding provenance. |
| Same-memory concurrent revisions produce conflicts rather than lost updates | Verified at the canonical engine seam | A PostgreSQL-backed stale-revision race produced the established conflict result without overwriting the winning revision. The regression uses the existing authorized revision binding; default Milestone 7 Codex credentials intentionally retain narrower read-and-nominate authority. |
| Every client and transport is distinguishable in audits | Verified | Two live direct-private diagnostics authenticated through separate credentials and produced two privacy-safe omission decisions and receipts with distinct actor, client, and transport-binding identities. |

## Implemented authentication boundary

ADR 0018 freezes request-scoped bearer authentication for the direct-private
listener. Tokens use a bounded versioned envelope with untrusted tenant and
credential lookup identifiers plus a random secret. PostgreSQL forced RLS
remains active; the tenant hint selects one RLS context and joined database
state establishes the actor, client, credential, binding, transport, and
capability authority.

Bearer verification uses a domain-separated HMAC-SHA-256 verifier and a
systemd credential that is absent from environment variables, command lines,
logs, and repository state. Authentication performs a scalar verifier lookup,
constant-time verification, then a locked second-phase lifecycle and identity
recheck. Revoked, expired, future-created, malformed, ambiguous, and
wrong-transport credentials fail closed without an identity oracle.

Every MCP tool resolves its principal from the current authenticated request.
Mutation, nomination, query, and status dispatch share the same proven
identity. The direct listener rejects relay, GitHub, archive, and internal
service bindings; those transports retain separate adapters.

Capability profiles are closed, versioned JSON. PostgreSQL JSONB hydration
uses strict JSON-mode validation and rejects duplicate, empty, malformed, or
unknown collections before set coercion. Operator metadata output sorts set
members deterministically and cannot represent a token or verifier.

## Codex integration and diagnostics

The repository includes direct-private and disabled relay configuration
examples, reusable `AGENTS.md` guidance, static server instructions, and a
payload-safe diagnostic CLI. The installed Codex release and current official
configuration documentation were checked for the Streamable HTTP URL and
bearer-token environment-variable settings.

Server instructions identify retrieved statements and evidence as untrusted
data, forbid executing embedded tool calls or policy overrides, and keep the
first 512 characters self-contained. Repository guidance does not permit
copying retrieved private memory into source or pull requests automatically.

Direct nominations ignore caller-supplied evidence references. Conservative
assistant observations receive one server-owned evidence source derived from
the authenticated actor, client, and binding. The source is stable across
idempotency keys, logical sessions, subagents, and credential rotation, so one
client cannot manufacture independent corroboration or self-promote a
candidate.

The diagnostic performs authentication, server-identity and tool discovery,
transport-status verification, a nonexistent-memory read, and an explicitly
confirmed routine-banter nomination. The write canary must be omitted without
an event, memory, evidence row, or outbox job; any durable result fails and
returns only a recovery identifier.

## Repository verification

The implementation passed the complete repository gate with the pinned pnpm
release:

```bash
make PNPM='npx --yes pnpm@10.15.0' verify
```

The source gate reported 1,005 Python tests passed and 159 PostgreSQL tests
skipped only because the workstation PostgreSQL installation lacks pgvector.
Ruff formatting and lint, strict mypy over 249 files, Go module verification,
vet and tests, deterministic protobuf generation, 11 JSON Schema contracts,
Biome, TypeScript, and the plugin privacy test all passed.

## Disposable PostgreSQL 17 acceptance

The exact `8b01b22` source archive was checksum-verified and extracted into a
fresh disposable directory. Tests ran as the unprivileged Memory Node service
account with PostgreSQL 17, pgvector, an explicit PostgreSQL binary directory,
and required-database mode.

The complete integration suite reported:

```text
174 passed, 18 warnings in 234.08s
```

The warnings are limited to the documented SQLAlchemy/Alembic metadata
comparison limitations for deliberate cyclic foreign keys and PostgreSQL
trigram operator classes. There were no skips or failures. Coverage included
the full migration chain through `0008_codex_credentials`, the pre-0008 role
bootstrap sequence, credential create/list/authenticate/rotate/revoke, role
and RLS matrices, concurrent Codex nominations, stable evidence independence,
idempotent replay, stale-revision conflict behavior, archive restore, ingress,
retrieval, and readiness.

Acceptance exposed and closed four release blockers before activation:

- the current role bootstrap referenced credential columns before migration
  `0008` introduced them;
- strict Python-mode validation could not rehydrate valid JSONB capability
  arrays and would have disabled bearer authentication;
- JSON set coercion required explicit duplicate rejection to prevent malformed
  stored authority from being normalized silently; and
- two PostgreSQL regressions used non-production ownership and stale audit
  timestamps.

## Live cutover evidence

Writers were stopped before migration. A fresh protected pre-cutover backup
passed SHA-256 and `pg_restore --list` verification. The canonical database
advanced transactionally from `0004_genesis_import_provenance` through
`0008_codex_credentials`, followed by the exact least-privilege role
bootstrap. Object ownership, forced RLS, immutable/lifecycle triggers, role
attributes, compatibility metadata, and baseline row counts were checked
before any credential was issued.

Two environment-specific Codex installations were provisioned exactly once.
Each has one actor, client, direct-private binding, active bearer credential,
and protected one-time token file. Repeated provisioning checks require either
an entirely absent state or an exact one-to-one persisted state plus token
file; mixed or duplicated state fails closed. The live readback reused the two
existing installations and created no additional rows.

The API and tunnel run from the immutable `8b01b22` release and listen only on
loopback. Health and authenticated-runtime readiness return success. Two live
diagnostics produced exactly these database deltas:

```text
memory_events       +0
memories            +0
memory_evidence     +0
outbox_jobs         +0
selection_decisions +2  (routine_banter / omit)
command_receipts    +2
```

Both credentials recorded successful use, and the two new decisions have
distinct actor, client, and transport-binding provenance with null event and
memory identifiers. A protected post-cutover backup was created at
`/mnt/memory/kivra-memory/backups/post-m7-cutover-20260809T172242Z` and passed
checksum and restore-list verification. The previous production release and
the pre-cutover backup remain available for recovery.

## Deliberate activation boundary

Archive export, GitHub ingress, and sealed-content purge services remain
inactive. Milestone 7 did not fetch, install, or execute the separate memory
ingress repository. If a later approved activation needs that repository, its
source must resolve exactly to commit
`84233835924ade0e3cf26bb995717c880c75ff5c` before any ingress state is
registered. This pin does not authorize activation or duplicate existing
ingress objects.

Relay-backed remote Codex mutation remains a later milestone. The checked-in
relay example stays disabled, and direct-private credentials cannot be reused
as relay identities. No Git remote was pushed during Milestone 7 acceptance.
