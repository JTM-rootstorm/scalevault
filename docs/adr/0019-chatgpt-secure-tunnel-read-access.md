# ADR 0019: ChatGPT secure-tunnel read access

- Status: Accepted
- Date: 2026-08-09
- Supersedes: None
- Extends: ADR 0001, ADR 0006, ADR 0011, ADR 0016, and ADR 0018

## Context

ScaleVault needs a bounded ChatGPT-facing read surface without turning a public
tunnel into a command path or reusing a direct-private Codex identity. The
OpenAI tunnel client has separate control-plane credentials and can inject a
static Authorization value from a protected file into requests sent to the
Memory Node. Neither the tunnel control plane nor caller-supplied request data
is a ScaleVault identity claim.

A single tunnel may otherwise fan multiple ChatGPT workspaces or applications
into one indistinguishable principal. That would make audit attribution and
revocation ambiguous. Secure-tunnel identity must therefore describe one
intended workspace or application association and fail closed if that contract
is changed or broadened.

## Decision

### Endpoint and tool surface

The ChatGPT adapter is a distinct HTTP MCP endpoint at `/chatgpt/mcp`. It is
reachable only through the reviewed secure-tunnel deployment path; the Memory
Node retains a non-public listener. The adapter constructs exactly these ten
existing read/status tools and no other MCP `Tool` objects:

1. `memory_context_pack`
2. `memory_search`
3. `memory_get`
4. `memory_timeline`
5. `memory_conflicts`
6. `memory_lineage`
7. `memory_selection_history`
8. `memory_ingress_status`
9. `memory_transport_status`
10. `memory_selection_decisions`

Mutation, nomination, and administrative tools are absent. The adapter creates
only a request-local `QueryPrincipal`. It does not create or reuse a
`CommandPrincipal`, `AuthenticatedRequestIdentity`, or the direct-private
`StatusIdentity`. Registering ten tools does not grant them: each invocation
still requires its exact dotted scope. `memory_ingress_status` remains an opaque
ID lookup masked to ingress owned by the authenticated actor.

This decision does not provide mobile access, GitHub proposal creation, memory
nomination, or any other write capability.

### Bearer and transport binding

The injected MCP Authorization value uses the ADR 0018 `svb1` token and HMAC
verifier contract. It is distinct from the tunnel client's OpenAI control-plane
credential. A control-plane credential cannot authenticate to ScaleVault, and
a ScaleVault bearer cannot authenticate the tunnel client to OpenAI.

Every request performs ADR 0018 lookup, HMAC verification, and locked database
active-state recheck. The trusted server configuration supplies
`TransportKind.SECURE_TUNNEL` and one pinned UUIDv7 installation ID. The joined
database state must establish all of the following:

- an active tenant;
- an unrevoked `agent` actor whose metadata is exactly
  `{"provisioning_contract":"scalevault-chatgpt-secure-tunnel-v1"}`;
- an unrevoked `interactive` client with transport `secure_tunnel`;
- an unexpired binding with disclosure boundary `openai_secure_tunnel`, the
  pinned installation, and exactly `{"operations":[]}`;
- an unrevoked installation whose capability profile is exactly
  `{"association_mode":"single_chatgpt_workspace","contract_version":"scalevault-secure-tunnel-installation-v1"}`;
- unique scopes drawn only from the seven ADR 0011 semantic read scopes and
  `memory.status.ingress` and `memory.status.transport`; and
- a strict `scalevault-client-capability-v1` read profile.

Unknown fields, write scopes, non-empty operations, mismatched installation,
revoked components, or identity-kind drift fail authentication. Revocation is
checked from PostgreSQL for every request; no successful identity is cached
across requests. Requests authenticated before a later revocation commit may
finish, but no request authenticates after that commit.

One actor may be shared with a separately configured GitHub ingress identity,
but the secure-tunnel client, binding, installation, and bearer are distinct.
One secure-tunnel installation represents one intended ChatGPT workspace or app
association. Connecting another workspace or app requires a separately issued
client, installation, binding, and credential. Multi-workspace fan-in under one
identity is forbidden.

### Issuance, retry, and recovery

Secure-tunnel issuance and rotation require `--secret-output`; stdout secret
output is unavailable. The root-operated credential administrator creates a
single-link, root-owned, mode-0600 regular file containing exactly the complete
header value `Bearer svb1...` plus one trailing newline. It uses no-follow and
exclusive-create behavior, writes and fsyncs the protected artifact before the
database transaction commits, and never silently replaces an existing path.

On retry, the administrator validates the existing protected artifact and
derives its tenant and credential UUIDs. It returns an existing database
credential only when that UUID and all safe immutable actor, client, binding,
installation, profile, scope, operation, expiry, public-hint, and verifier-key
identifier fields match the requested contract. The credential-admin role
cannot select the stored verifier, so retry does not claim verifier equality.
A mandatory authenticated read smoke is required before service activation and
detects verifier corruption by failing closed.

A database row with no matching artifact, an artifact with no matching row,
or any partial or conflicting identity state is a hard operator-recovery
failure. If the database rejects an operation after artifact creation, the CLI
reports that the protected artifact may require recovery; it never deletes or
replaces that evidence automatically. Rotation publishes a new protected path,
revokes the prior credential atomically with inserting the replacement, and is
retry-safe by the replacement credential UUID and safe immutable state.

The credential-administrator role has only the exact identity, installation,
binding, and credential column privileges needed for this lifecycle. It cannot
read bearer verifiers, delete identity rows, or read memory, event, evidence,
or sealed-content payloads.

ADR 0015 intentionally archives the actor, client, installation, and binding
but excludes credential material. Disaster-recovery reissue is therefore a
separate root-only operation, never an implicit create-or-load relaxation. It
requires explicit tenant, actor, client, binding, and installation UUIDv7
selectors; proves the exact active ADR 0019 identity, profile, scope, and empty-
operations contract; and requires zero credential rows for that client and
binding. It then inserts one new bearer credential only. A retry may return
that one replacement only when the protected artifact UUID and safe state
match. Any prior credential row, partial identity, drift, or selector mismatch
fails closed. The operation cannot alter or delete restored identity rows.

## Consequences

- ChatGPT receives a useful read/status surface without a command principal.
- Secure-tunnel requests have stable, database-derived attribution and
  request-by-request revocation.
- A second workspace cannot silently share the first workspace's audit
  identity; it must be separately provisioned and revoked.
- The protected Authorization artifact is operationally sensitive and requires
  root-only backup and explicit mixed-state recovery.
- Service activation requires both deployment preflight and one authenticated
  read smoke; schema readiness alone is insufficient.
