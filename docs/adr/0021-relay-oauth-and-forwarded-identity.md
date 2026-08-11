# ADR 0021: Relay OAuth and forwarded request identity

- Status: Superseded
- Date: 2026-08-10
- Supersedes: None
- Superseded by: ADR 0022
- Extends: ADR 0001, ADR 0008, ADR 0010, ADR 0011, ADR 0017, ADR 0018, ADR 0019, and ADR 0020

## Context

ADR 0020 authenticates a private node installation to the relay. It does not
authenticate the public user, bind that user to an installation, or authorize a
request at the canonical Memory Node. The public OAuth bearer cannot simply be
forwarded: doing so would expose a reusable credential to another trust
boundary and would let relay headers select canonical identity.

The current direct-private identity contract requires a canonical bearer
credential and intentionally rejects relay traffic. The canonical schema also
has no external OAuth-subject binding or concurrent assertion-replay store.
Those gaps must be resolved before public `/mcp` routing is enabled.

OpenAI's current MCP guidance requires protected-resource metadata, OAuth 2.1
authorization code with PKCE, a resource indicator preserved through token
issuance, per-request issuer/audience/expiry/scope checks, and a maintained
identity provider rather than a new general authorization server. Product
capability remains a dated deployment observation; this ADR freezes
ScaleVault's side of the security contract.

## Decision

### Public resource and provider profile

The public MCP resource is one byte-exact, operator-configured HTTPS URI ending
in `/mcp`, for example `https://relay.example.invalid/mcp`. It does not encode
an installation ID, private hostname, tenant, or user coordinate. This replaces
installation-subdomain examples in the implementation plan for the generic
plugin profile. The same complete URI is used in protected-resource metadata,
the OAuth authorization and token `resource` parameter, JWT audience, relay
binding, forwarded assertion, and canonical subject HMAC. Installation
selection is an authorization decision stored server-side.

The relay resource facade serves:

```text
GET /.well-known/oauth-protected-resource
GET /.well-known/oauth-protected-resource/mcp
GET /mcp
POST /mcp
```

Both well-known routes return equivalent metadata. Standalone `GET /mcp`
returns HTTP 405 with `Allow: POST`; stateless v1 does not create a server-
initiated SSE stream. A missing, invalid, or expired token returns HTTP 401 with
one bounded `WWW-Authenticate` challenge:

```text
Bearer error="invalid_token", error_description="Authentication required", resource_metadata="<exact protected-resource metadata URL>"
```

A valid token lacking a required scope returns HTTP 403 with:

```text
Bearer error="insufficient_scope", error_description="Additional authorization required", scope="<sorted exact scopes>", resource_metadata="<exact protected-resource metadata URL>"
```

The descriptions are those fixed ASCII strings and never include validation
details. The scope field is one sorted, space-delimited list with no duplicate
values. Metadata names one maintained, self-hosted OAuth 2.1/OIDC issuer, the
exact resource URI, and supported scopes. The issuer publishes standard
authorization-server or OIDC discovery metadata.

The initial provider profile requires:

- authorization-code flow with S256 PKCE;
- exact redirect URI and state validation;
- the RFC 8707 `resource` value echoed into a JWT access-token audience;
- predefined, operator-allowlisted public OAuth client IDs for ChatGPT and
  Codex v1; CIMD and DCR are disabled so the provider never fetches an
  attacker-selected client metadata URL;
- signed JWT access tokens using RS256 or ES256, exact issuer,
  audience, expiry, not-before, subject, authorized-party/client ID, and scope
  claims; and
- explicit token, grant, client, and subject revocation procedures.

Access tokens are compact JWTs no larger than 16 KiB. Their protected header
contains only `alg`, a 1-to-64-byte safe ASCII `kid`, and optional `typ=at+jwt`;
remote-key headers and unknown fields are rejected. `iss`, case-sensitive
`sub`, exact string `aud`, string `client_id`, integer `iat`/`nbf`/`exp`, and a
space-delimited string `scope` are required. Optional `azp`, when present, must
equal `client_id`. Scopes are unique known values; input ordering conveys no
authority. Token lifetime is at most five minutes.

JWKS is fetched only from the exact configured issuer discovery result through
an egress allowlist, with HTTPS, public-address resolution, redirect rejection,
one-second connect and five-second total timeouts, a 1 MiB response limit, JSON
content type, and bounded refresh rate. A positive key set may be cached for at
most five minutes; an expired cache or unknown `kid` fails closed. Binding,
client, installation, and grant revocation is checked from relay storage on
every request. Provider-side token revocation takes effect no later than the
five-minute token expiry.

Opaque tokens and introspection are not supported in v1. Unknown token formats,
algorithms, issuers, clients, claims, or scopes fail closed. The OAuth provider
owns authorization codes, access and refresh tokens, login sessions, and its
database. None of that material enters the relay operational database.

ChatGPT public-read and remote-Codex read/write use separate OAuth clients and
canonical relay identity bindings. ChatGPT mTLS may identify the OpenAI-hosted
client at the public edge, but it never identifies the end user and never
replaces OAuth. Codex uses OAuth for the public relay; the disabled bearer-token
example is removed when this profile is activated.

### External subject and installation binding

OIDC `sub` is opaque and case-sensitive. It is never case-folded, trimmed, or
interpreted as an email address. The issuer URL is canonicalized only by the
deployment's exact configured value. The resource and OAuth client/authorized
party remain part of identity because pairwise subjects may differ by client.

The relay database adds an active external binding keyed by:

```text
external_issuer, external_subject, oauth_client_id, resource,
tenant_id, installation_id, capability_profile, capability_contract_version,
allowed_scopes
```

The tuple `(external_issuer, external_subject, oauth_client_id, resource)` maps
to exactly one active tenant and installation independent of the capability
profile. A profile may narrow that one mapping but cannot select another
tenant or installation. The record stores no access token, refresh token,
authorization code, email,
profile claim, memory identifier, or canonical actor/client UUID. Binding
creation, installation selection, replacement, and revocation are operator or
authorization-facade actions with content-free audit metadata.

A request is routable only when these identities agree:

1. the exact public resource, OAuth issuer, token audience, and OAuth client;
2. the external subject's active tenant, installation, and capability binding;
3. the connected node's active mTLS tenant and installation; and
4. the Memory Node's active external mapping, relay client, transport binding,
   and installation.

An ambiguous, offline, expired, or revoked component fails closed without
revealing which binding check failed.

### Authorization facade and request integrity

The authorization facade is a narrow, separately isolated process in front of
the relay router. It validates the public bearer on every request, performs the
external binding lookup, applies the 1 MiB ADR 0020 request limit, and buffers
the request body only in bounded process memory. It never writes the body to a
database, file, log, trace, retry queue, or crash dump.

After token verification, the facade parses only the bounded JSON-RPC envelope
and, for `tools/call`, `params.name`; it does not parse or authorize tool
arguments. This lets it apply the exact token-scope requirement for the named
tool. A transport authentication or token-scope rejection returns the HTTP
401/403 challenge above and never claims to be an MCP tool result. A malformed
envelope fails closed before assertion issuance. The relay router remains
unaware of MCP methods, tool names, and payload semantics.

The facade computes SHA-256 over the exact request-body bytes before issuing an
assertion. It then removes `Authorization` and passes the body, normalized
content metadata, and assertion to the relay router. A compromised router can
drop or replay a request but cannot change its body, identity, method, path,
content type, or protocol version without detection at the Memory Node. The
facade remains in the plaintext trust boundary and must satisfy the same
no-persistence and no-payload-logging rules as the relay.

Buffering is admitted before reading a body. The facade and Memory Node each
permit at most four hashing buffers per external binding, 32 per installation,
and 64 MiB of aggregate hashing-buffer reservations across the process. Each
reservation is the declared request limit, not the bytes received so far. A
request that cannot reserve its complete budget is rejected before its body is
read. These limits are independent of the transport's in-flight request limits
and make the 1 MiB per-request ceiling an aggregate bound rather than a
potential GiB-scale allocation.

### Assertion format and keys

The forwarded assertion is a compact JWS using JWT claims, Ed25519, and
`alg=EdDSA`. The protected header contains exactly:

```json
{"alg":"EdDSA","kid":"<operator-assigned-key-id>","typ":"sv-relay-assertion+jwt"}
```

`kid` is 1 through 64 ASCII letters, digits, dots, underscores, or hyphens.
`crit`, `jku`, `jwk`, `x5u`, `x5c`, and all unknown protected headers are
forbidden. The compact assertion is at most 8 KiB. JSON duplicate keys,
non-integer NumericDate claims, invalid UTF-8, and unrecognized claims fail
closed.

The authorization facade signing key is separate from TLS, node-client CA,
OAuth-provider, bearer-pepper, archive, and content keys. The Memory Node never
fetches assertion keys from the relay or a request-supplied URL. Operators
provision a root-owned, mode-0600 JWKS credential containing only reviewed
Ed25519 public keys. Rotation adds a new key before issuance switches, retains
the old public key for no longer than the assertion lifetime plus ten minutes,
and removes it explicitly. Emergency revocation removes the key and rejects all
assertions bearing its `kid`.

The claims are exactly:

```text
iss, ext_iss, sub, client_id, resource, aud, tenant_hint, installation_id,
capability_profile, scope, iat, nbf, exp, jti, request_id,
method, path, content_type, mcp_protocol_version, body_sha256
```

`iss` is the assertion-facade issuer, distinct from OAuth `ext_iss`. `sub` is
the exact external OAuth subject. `aud` is the fixed string
`scalevault:memory-node:relay`. `method` and `path` are the normalized upstream
values `POST` and `/relay/mcp`; they must equal the gRPC request-start envelope.
`request_id` equals the gRPC lowercase UUIDv7 request ID. `installation_id` and
`jti` are lowercase UUIDv7 values. `tenant_hint` is a lowercase UUIDv7 used only
to enter tenant RLS; it is not an identity claim and the selected row must
rederive the same tenant from the external tuple and installation. `scope` is a
sorted, space-delimited exact allowlist. `body_sha256` is the unpadded base64url
SHA-256 digest of the exact forwarded bytes. Content type and MCP protocol
version are canonical ASCII values from the validated request headers. On the
initial request, the absent `MCP-Protocol-Version` header is represented by the
literal `initial`; after digest verification the Memory Node requires that body
to be the JSON-RPC `initialize` method. Every later assertion binds the exact
validated header.

`iat`, `nbf`, and `exp` are integer UTC seconds. Lifetime is at most 30 seconds,
future issuance is tolerated by no more than five seconds, and an assertion
must remain valid when canonical replay consumption commits. Apart from the
non-authoritative `tenant_hint`, assertion claims contain no canonical tenant,
actor, client, binding, credential, visibility, sensitivity, or memory
identifier.

The assertion is carried only in `ScaleVault-Relay-Assertion`. A public header
with that name, including any case variant or duplicate, is rejected. The node
agent treats it as opaque. The Memory Node verifies the signature and all
claims, streams the bounded body while recomputing SHA-256, and does not invoke
the MCP application until the digest matches.

### Canonical external identity and replay schema

The Memory Node adds `relay_external_identities` with tenant RLS and these
identity columns:

```text
relay_external_identity_id, tenant_id, assertion_issuer,
external_issuer, external_subject_hmac, external_subject_hmac_key_id,
oauth_client_id, resource,
installation_id, actor_id, client_id, transport_binding_id,
capability_profile, capability_contract_version, allowed_scopes,
created_at, expires_at, revoked_at
```

`tenant_hint` establishes ordinary tenant RLS before lookup, exactly as the
untrusted direct credential tenant locator does in ADR 0018. It is fully
revalidated and cannot widen authority. `external_subject_hmac` is HMAC-SHA-256
under the key named by `external_subject_hmac_key_id`, using a node-only,
versioned external-subject pepper over length-delimited assertion issuer,
external issuer, exact subject UTF-8 bytes, OAuth client ID, and resource.
PostgreSQL stores no raw external subject. One active row is unique for the full
external tuple independent of capability profile. Foreign keys and triggers
require an active relay client,
`public_relay` transport binding, matching tenant and installation, and the
profile's exact operation set. Deletes and identity-field updates are
forbidden; revocation is append-preserving.

The Memory Node also adds `relay_assertion_replays` under tenant RLS:

```text
tenant_id, assertion_issuer, assertion_id, request_id,
relay_external_identity_id, expires_at, consumed_at
```

The primary key `(tenant_id, assertion_issuer, assertion_id)` and unique
`(tenant_id, request_id)` make concurrent replay consumption atomic. The row
contains no body digest, subject, scope, assertion, or payload. It is inserted
in the same transaction that locks and rechecks the external identity, tenant,
actor, client, transport binding, and installation. A uniqueness conflict,
database outage, expired assertion, or cleanup ambiguity rejects the request.
Rows may be purged only after `expires_at` plus ten minutes.

### Request identity and principal derivation

Relay authentication produces a new `RelayRequestIdentity` storage result with
the canonical tenant, actor, client, transport binding, installation, external
binding ID, scopes, capability profile, and authorized operations. It does not
manufacture a canonical bearer credential.

`StatusIdentity` becomes transport-neutral by allowing exactly one of
`credential_id` or `relay_external_identity_id`. Direct-private identities keep
their credential and `private_node` boundary. Relay identities require the
external identity ID, `TransportKind.RELAY`, `public_relay`, and a matching
installation. Existing command and query principals remain unchanged, so all
mutations still enter ADR 0010 domain command handlers and preserve canonical
event provenance.

The node and facade use a reviewed, byte-identical
`scalevault-public-relay-profile-v1` registry. Profile objects are closed: the
only accepted fields are `contract_version`, `profile_id`, `tool_names`,
`allowed_scopes`, `authorized_operations`, `read_capability`, and
`confirmation_required_for_writes`. Unknown or changed fields and values fail
closed.

Both v1 profiles have these exact read scopes:

```text
memory.read.conflicts memory.read.context memory.read.get
memory.read.lineage memory.read.search memory.read.selection_history
memory.read.timeline memory.status.ingress memory.status.transport
```

Their read capability uses the existing capability dictionary with memory
scopes `global`, `persona`, `relationship`, `project`, and `episodic`;
visibility values `private_root`, `restricted`, `shareable`, and `public_seed`;
maximum sensitivity 3; and candidates excluded. Canonical client and binding
state can narrow every value.

`chatgpt_public_plugin_read` exposes exactly the ten tools named in the public
plugin profile, has only the nine read/status scopes above, has an empty
`authorized_operations` list, and has no write confirmation boundary because
writes are absent.

`codex_public_relay` exposes those ten read tools plus `memory_nominate`,
`memory_link`, `memory_open_conflict`, `memory_resolve_conflict`,
`memory_retire`, and `memory_forget`. It adds exactly these scopes:

```text
memory.write.conflict.open memory.write.conflict.resolve
memory.write.forget memory.write.link memory.write.nominate
memory.write.retire
```

Its approved event operations are exactly `observed`, `remembered`, `linked`,
`conflict_opened`, `conflict_resolved`, `retired`, and `tombstoned`, and normal
write confirmation remains required. The direct legacy operations
`memory_observe`, `memory_remember`, and `memory_revise` are not available from
the v1 public Codex profile. The external binding's `allowed_scopes` must be a
duplicate-free subset of its profile scopes, and the canonical external row
must store the same set and `capability_contract_version`, whose only accepted
v1 value is `scalevault-public-relay-profile-v1` and which must equal the
registry object's `contract_version`. Drift between the two copies or between
either copy and the closed registry fails closed.

Effective authority can only narrow. It is the intersection of the access
token's asserted scopes, the relay external binding's allowed scopes, the
canonical client's active scopes, the canonical transport binding's allowed
operations, and the capability-profile ceiling. An operation must have both an
effective scope and an allowed canonical operation; a coarse scope such as
`memory:write` does not bypass a missing operation. Tool discovery and tool
invocation use the same derived authority snapshot, and each request rechecks
revocation before consuming its assertion replay row.

Tool discovery is request-local and derived from the authenticated canonical
profile. The same public URL may therefore return a physically read-only
registry to ChatGPT and a separately scoped registry to Codex. The relay does
not inspect MCP JSON to choose tools and installation alone never implies write
capability. A dormant `chatgpt_public_plugin_full` profile requires a later
dated capability decision before it can be issued.

Every authenticated tool descriptor includes one MCP `oauth2`
`securitySchemes` entry containing that tool's exact minimum canonical scope or
scopes. The ten public-read tools use their existing `memory.read.*` or
`memory.status.*` scope; mutation tools use their existing exact
`memory.write.*` scope. The descriptor scopes must equal the invocation check
and cannot advertise a coarse substitute.

The dedicated Memory Node relay authentication adapter is the only layer that
produces MCP authentication results. For `tools/call`, if an already accepted
request later fails canonical identity or revocation validation, the adapter
returns a protocol-valid tool error with HTTP 200 and
`_meta["mcp/www_authenticate"]` set to a single-element JSON array containing
the exact `invalid_token` challenge above. If canonical effective authority
lacks a scope required by an otherwise visible tool, it returns the exact
`insufficient_scope` challenge with the same scope ordering and shape.

For `initialize`, `tools/list`, ping, and other request methods, the same
canonical identity or revocation failure is a relayed HTTP 401 with the exact
`invalid_token` challenge and a bounded JSON-RPC error preserving the request
ID; it is never encoded as a tool result. An authentication failure on a
notification returns HTTP 401 with no JSON-RPC response body and causes no
state transition. A non-tool method with insufficient canonical scope returns
the analogous HTTP 403 challenge. One request never returns both a transport
401/403 and an MCP tool result. Contract tests for descriptor, HTTP rejection,
non-tool requests, notifications, and runtime tool-result surfaces are
release-blocking.

Loss of the public HTTP delivery connection is not itself cancellation. Before
the Memory Node accepts a verified request, the facade may abandon it without
starting canonical work. After acceptance, canonical work is cancelled only by
an explicit MCP cancellation notification, the request deadline, revocation of
the bound identity or installation, controlled shutdown, or internal resource
exhaustion. The relay may discard an undeliverable response, but it must not
translate an HTTP disconnect into an ADR 0020 `CLIENT_CLOSED` cancellation or
automatically replay the request. This rule narrows ADR 0020 for public MCP
traffic; callers retry mutations with the same canonical idempotency key.

### Failure, privacy, and deployment

OAuth, assertion, external mapping, replay, installation, scope, and canonical
binding failures use bounded, content-free errors. Missing, invalid, and
expired authentication retain the required HTTP 401 distinction; a valid token
with insufficient scope retains HTTP 403. Neither class reveals which internal
binding check failed. Token claims, subjects, assertions, digests, keys, header
values, and database errors do not appear in logs, metrics labels, traces, or
responses. Request and response body privacy remains governed by ADR 0020.

Public activation requires a verified provider configuration, protected-
resource and authorization-server metadata probe, redirect/client registration
probe, domain verification, current tool scan, reviewer-safe tenant, and live
Codex/ChatGPT acceptance. The canonical Memory Node LXC remains private.

## Consequences

- OAuth user identity, node mTLS identity, and canonical memory identity remain
  distinct and must all agree.
- A compromised relay router without access to the facade signing credential
  cannot alter or mint an authorized request. Compromise of the facade or the
  whole relay host can impersonate external subjects until its assertion key is
  revoked; process isolation reduces blast radius but does not remove that
  trust.
- Public ChatGPT discovery is physically read-only while remote Codex can use a
  separately scoped profile at the same stable URL.
- Two new canonical tables and a transport-neutral status identity require a
  coordinated migration and application review.
- Public deployment remains disabled until the provider, host, metadata,
  domain, and live account gates are actually completed.

## Current compatibility source

The OAuth and public submission requirements used for this decision were
verified on 2026-08-10 against the official OpenAI authentication guidance:
<https://developers.openai.com/plugins/build/auth>.
