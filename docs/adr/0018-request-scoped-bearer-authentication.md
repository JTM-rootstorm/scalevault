# ADR 0018: Request-scoped bearer authentication

- Status: Accepted
- Date: 2026-08-09
- Supersedes: None
- Extends: ADR 0001, ADR 0008, ADR 0010, ADR 0011, ADR 0016, and ADR 0017

## Context

The Memory Node already records tenants, actors, clients, credentials, transport
installations, and immutable transport bindings. Its command and query engines
also accept typed principals that adapters must derive from authenticated
context. The production MCP surface nevertheless has no accepted contract for
turning a Codex bearer credential into those principals.

Accepting tenant, actor, client, installation, scope, sensitivity, or transport
claims from tool arguments or unverified headers would break the authority
boundary. Looking up a credential inside tenant row-level security is also
impossible before the tenant is authenticated. Direct, secure-tunnel, relay,
GitHub-ingress, internal-service, and archive-restore identities must not become
interchangeable merely because they share application principal types.

## Decision

### Token and verifier contract

Private Codex clients use one independently revocable bearer credential per
host or environment. Version one tokens have exactly this ASCII shape:

```text
svb1.<lowercase tenant UUIDv7>.<lowercase credential UUIDv7>.<43-character unpadded base64url secret>
```

The secret is 32 uniformly random bytes. The tenant UUID is an untrusted RLS
lookup hint and the credential UUID is a public lookup locator; neither is an
identity claim. A token is accepted only from a single `Authorization`
header using the case-insensitive `Bearer` scheme, one ASCII space, and no
other whitespace, parameters, commas, or surrounding text.

PostgreSQL stores only this versioned verifier:

```text
hmac-sha256-v1:<43-character unpadded base64url digest>
```

The digest is HMAC-SHA-256 under a server-only pepper over the ASCII bytes
`scalevault-client-bearer-token-v1`, one zero byte, and the entire canonical
token. The pepper is at least 256 bits, is provisioned through
an OS credential boundary, is distinct from content-encryption and digest-
binding keys, and is excluded from PostgreSQL, logs, archives, and backups of
canonical memory data. Verification uses constant-time comparison. Rotation
requires an explicit dual-verifier or credential-reissue procedure; silently
trying unrelated keys is forbidden.

The production process reads the systemd materialized credential only when it
is a single-link regular file owned by the effective service UID, has no group
or world permission bits, and contains 32 through 128 bytes. This pins the
runtime check to the ownership produced for the service user rather than the
root-owned source credential.

All parsing, lookup, verifier, revocation, expiry, and binding failures expose
one safe `authentication failed` result. Authorization values, token
fragments, verifier strings, credential hashes, and database exception text
must not appear in logs, metrics labels, errors, reprs, or traces.

### Identity lookup and active-state checks

The tenant hint is used only to establish ordinary tenant RLS for a read-only
credential lookup. The selected row must match both token UUIDs. The lookup
returns only the verifier and its pepper key identifier. After constant-time
verification, persistence locks and rechecks the credential and joined tenant,
client, actor, transport binding, and optional installation before recording
successful use and returning identity. The database join, not either token
UUID, determines the authenticated identity.

Authentication verifies the secret and then requires all of the following at
one database snapshot and one server time:

- the credential is a bearer credential, is not revoked, and has not expired;
- the tenant is active and the actor and client are not revoked;
- the credential belongs to the joined client;
- exactly one current transport binding matches the client, actor, tenant, and
  trusted request transport;
- the client transport and binding transport agree;
- the binding has not expired and its disclosure boundary is the canonical
  boundary for that transport;
- an installation, when present, matches trusted transport context and is not
  revoked; and
- client scopes, read capabilities, and binding operations pass their strict,
  versioned schemas.

No caller-provided tenant, actor, client, binding, installation, or scope is
accepted. Ambiguous rows and unknown capability fields fail closed.

### Transport separation

Milestone 7 authenticates only a server-configured `direct_private` request
context. It does not authenticate `secure_tunnel`, `relay`, `github_ingress`, `internal_service`, or
`archive_restore` contexts.

Relay requests require the separately reviewed signed external-subject and
installation-binding contract. GitHub proposals retain their pinned ingress
identity and immutable ingress provenance. Worker, importer, purge, and restore
principals remain locally pinned service identities. A valid direct bearer can
therefore never select or inherit one of those transports.

### Capability mapping

Authentication produces one immutable `AuthenticatedRequestIdentity` with:

- a `CommandPrincipal` containing only fine-grained write scopes whose event
  operations are also authorized by the immutable transport binding;
- a `QueryPrincipal` containing only supported read/status scopes and the
  server-validated read capability profile for allowed semantic scopes,
  visibilities, sensitivity ceiling, and candidate access; and
- a content-free `StatusIdentity` containing the authenticated UUIDs and exact
  transport/disclosure/installation identity for diagnostics and audit wiring.

The client capability contract is `scalevault-client-capability-v1`. New
credentials never receive `memory.write.legacy_v1` or aggregate legacy aliases
such as `memory:read` and `memory:write`. Database event provenance checks remain mandatory; authentication is
not a replacement for transaction-time binding validation.

Authentication is performed for every MCP request. A successful result is not
cached across requests. Implementations may cache only non-authoritative
parsing work; revocation and binding validity must take effect on the next
database lookup.

### Direct nomination provenance

Bearer authentication establishes a source identity, not the truth of a
nomination. The direct nomination resolver never trusts or persists evidence
keys or opaque references supplied by the MCP caller. For the constrained
assistant-observation candidate shape defined by ADR 0013, the server derives
one stable source key from canonical JSON containing exactly the authenticated
tenant, actor, client, and transport-binding UUIDs. The key excludes the bearer
credential, logical session, command and receipt identifiers, idempotency key,
and nomination payload. It is therefore stable across credential rotation and
subagent or session changes for one provisioned client, but differs for a
different client.

The resulting `trusted` evidence classification means only that those source
anchors passed request-scoped authentication. It is not user testimony,
semantic validation, or independent corroboration. Repeated observations from
the same source key cannot count as new candidate evidence or promote a
candidate. Credentials eligible for this path are provisioned as direct,
interactive agent clients with the exact nomination capability; authentication
does not infer that role from a caller claim.

## Consequences

- Every Codex host can be distinguished and revoked independently in audit
  provenance.
- The untrusted tenant hint can cause only an ordinary tenant-scoped lookup;
  mismatched tenant or credential locators fail authentication.
- HMAC verification is fast, so deployment rate limits and connection limits
  remain necessary against online guessing; 256-bit token entropy prevents
  practical offline guessing after verifier disclosure without the pepper.
- Losing the pepper invalidates bearer credentials but does not affect
  canonical memory or sealed-content recovery. Clients must be reissued.
- Relay identity, OAuth, certificate, issuance CLI, and rotation workflows need
  later contracts and cannot reuse this direct bearer adapter implicitly.
