# ADR 0020: Relay enrollment and bounded transport

- Status: Accepted
- Date: 2026-08-10
- Supersedes: None
- Extends: ADR 0001, ADR 0006, ADR 0008, ADR 0010, ADR 0017, and ADR 0018

## Context

ScaleVault needs a stable public relay without exposing the canonical Memory
Node. A node agent opens an outbound connection from the private trust boundary
and forwards only to the Memory Node. The existing relay protobuf and Go code
prove a single bounded echo stream; they do not define production enrollment,
peer identity, multiplexing, revocation, or retry behavior.

This decision freezes node enrollment, mTLS connection identity, and the
bounded transport state machine. A later ADR must freeze public OAuth identity,
subject-to-installation mapping, signed request assertions, identity-specific
tool discovery, and the dedicated Memory Node relay authentication adapter
before public `/mcp` routing is enabled. ADR 0018 continues to reject relay
traffic until that decision and implementation exist.

## Decision

### Relay persistence boundary

The relay uses a dedicated PostgreSQL 17 operational database in the relay
trust boundary. It is separate from the canonical Memory Node database and
from any maintained OAuth provider's database. Its Milestone 9 enrollment and
transport schema may persist only:

- tenant and installation routing identifiers;
- pairing-code verifier, expiry, attempt, consumption, and audit metadata;
- certificate serial, DER SHA-256 fingerprint, validity, rotation, and
  revocation metadata; and
- content-free connection, quota, health, and abuse-control metadata.

The relay database must not contain MCP request or response bodies, header
values, OAuth tokens or authorization codes, private keys, signed assertions,
free-text remote errors, retry bodies, or body spools. Database roles and
migrations enforce the allowlist. PostgreSQL, gRPC, and reverse-proxy payload
logging are disabled.

The relay terminates TLS and can observe live plaintext in process memory.
Documentation must state this honestly. Payload sealing or TLS passthrough is a
future protocol version, not an implied v1 property.

### One-use enrollment

Pairing is initiated only by an operator-local relay CLI. There is no public
pairing-code issuance endpoint. The CLI creates 32 uniformly random bytes,
encodes them as unpadded base64url, and shows the secret once. The database
stores only an HMAC-SHA-256 verifier under a relay-only pepper, tenant and
installation UUIDv7 values, creation time, and expiry no more than ten minutes
later. Verification is constant-time.

The node derives a fixed redemption path from its configured, CA-pinned relay
origin. The only unauthenticated enrollment route is:

```text
POST /v1/node-enrollments:redeem
```

The request accepts one pairing token and one PKCS #10 CSR in a JSON document
no larger than 16 KiB. Token syntax and request size are checked before CSR
parsing. Redemption is rate limited. An expired, consumed, malformed, or
mismatched code returns one safe failure.

The node enrollment CLI, running with root authority outside the long-lived
agent, generates an ECDSA P-256 private key and CSR locally. It writes the key,
certificate chain, and pinned trust material as single-link, root-owned,
mode-0600 regular files using no-follow, exclusive-create, fsync, and atomic
rename behavior. The node-agent service receives read-only material through
systemd credentials. The service never gains write authority over its source
credentials and no private key is printed or transmitted.

The relay ignores CSR subject and SAN requests, validates the CSR signature and
P-256 public key, and sets identity from its installation record. A node
certificate has `CA=false`, digital-signature key usage, client-auth EKU, no
unknown critical extensions, no DNS/IP/email SAN, and exactly one URI SAN:

```text
spiffe://scalevault/installation/<lowercase-installation-uuidv7>
```

The private node-client issuing CA is separate from public HTTPS/gRPC server
certificate trust and from later assertion-signing keys. The public relay
request process does not hold the issuing CA private key; a tightly scoped local
signer or offline operator boundary performs issuance. Certificate serials are
at least 128 random bits and unique. Node certificate identity is the SHA-256
digest of the complete DER certificate, not the SPKI.

Pairing-code consumption and certificate metadata commit atomically before the
response is sent. A lost response therefore produces a consumed-code recovery
case, never an automatic second issuance. The CLI does not replace or delete
credential artifacts automatically. The operator must revoke the orphaned
certificate record, inspect and preserve any local partial artifact, issue a
new pairing code, and retry with a fresh key and CSR. Database rollback leaves
the code unconsumed and no certificate recognized.

### Rotation and revocation

Node certificates live for at most 30 days and rotation begins with seven days
remaining. A connected node calls this mTLS-authenticated route with a new
locally generated CSR:

```text
POST /v1/node-certificates:rotate
```

The active certificate proves installation possession through mTLS; the CSR
proves possession of the new key. Issuance, preferred-fingerprint update, and
old-certificate overlap metadata commit atomically. The prior certificate may
remain valid for at most 24 hours so the operator can atomically publish the
new protected artifacts and restart the service. The relay operational
database owns the explicit certificate history and overlap set. The canonical
`transport_installations.node_certificate_sha256` value mirrors only the
preferred fingerprint and never represents caller identity or the overlap set.

Only one connection is active per installation. A new preferred-certificate
connection drains and replaces the old connection; an old-certificate
connection can never replace a preferred one. A certificate revocation cancels
its live connection within five seconds through database notification plus a
five-second active-state recheck. The same active installation may be paired
again only through an explicit operator recovery action. Installation
revocation is permanent: its UUID remains revoked for audit, all connections
close within five seconds, and re-enrollment creates a successor installation.

### mTLS connection identity

The node pins the relay server CA and exact TLS server name. The relay requires
a verified client certificate on the gRPC listener and derives installation
identity only from the verified URI SAN and active certificate row. It compares,
but never derives authority from, envelope installation fields. A certificate
mismatch, unknown installation, expiry, or revocation rejects the connection.

The handshake begins with a node hello and relay acknowledgement. The node
advertises protocol version `1`, its certificate-matching installation UUIDv7,
a fresh connection UUIDv7, exact capabilities, and supported limits. The relay
acknowledges the same installation and connection, selects version `1`, and
returns effective limits no greater than either peer's values. Requests before
acknowledgement are invalid. Handshake timeout is ten seconds.

V1 capabilities are exactly:

```text
mcp_streamable_http
relay_assertion_jws
bounded_multiplexing
```

V1 health states are `ready`, `degraded`, and `draining`. The node sends a
health heartbeat at least every 15 seconds while no other valid frame is sent;
the relay closes a connection after 30 seconds without any valid frame.
Unknown versions, capabilities, states, payload variants, duplicate IDs, or
state transitions fail closed.

### Additive protobuf evolution

The production protocol evolves the existing `scalevault.relay.v1` package
additively because the Milestone 0 probe was never deployed as a production
peer:

- add `NodeHello` and `RelayHello` oneof variants and a bounded `Limits`
  message;
- add an unsigned sequence field to `BodyChunk`;
- retain but deprecate `Cancelled.reason` and add a typed cancellation-code
  field; and
- retain but deprecate `RelayError.error_code` and `safe_message`, then add a
  typed relay-error-code field.

Production peers require hello/ack, typed codes, and sequence numbers and reject
the deprecated string fields. Existing field numbers and types are not reused.
The source protobuf and generated bindings must land together after this ADR,
with the normative relay protocol document updated in that same commit.

Cancellation codes are exactly `client_closed`, `deadline_exceeded`,
`queue_exhausted`, `installation_revoked`, `relay_shutdown`, and
`connection_lost`. Relay error codes are exactly `invalid_envelope`,
`unsupported_version`, `installation_mismatch`, `request_rejected`,
`upstream_unavailable`, `upstream_protocol`, `body_too_large`,
`headers_invalid`, `deadline_exceeded`, `queue_exhausted`,
`installation_revoked`, and `internal`.

### Fixed forwarding surface

Public OAuth and MCP routing remain disabled until the later relay-identity ADR.
When enabled, the public edge must validate the exact configured `Host` and
allowlisted `Origin` before stripping them. Duplicate singleton headers,
case-insensitive duplicates of reserved headers, and any public
`ScaleVault-Relay-Assertion` are rejected.

The node agent forwards only `POST /relay/mcp` to the literal loopback endpoint
`http://127.0.0.1:8080/relay/mcp` in the initial production profile. Redirects,
DNS names including `localhost`, alternate IPs, userinfo, query strings,
fragments, alternate paths, and alternate methods are forbidden. A later Unix
socket profile requires its own deployment decision and is not implied here.

Allowed forwarded request headers are `Content-Type`, `Accept`,
`MCP-Protocol-Version`, and the internally added
`ScaleVault-Relay-Assertion`. Allowed response headers are `Content-Type` and
`Cache-Control`. Authorization, cookies, host and forwarding headers, proxy
authorization, transfer framing, hop-by-hop headers, and unknown headers are
not forwarded.

### Bounds, state, and backpressure

Every installation, connection, request, and trace identifier is a lowercase
UUIDv7. Request and trace IDs are unique within a connection epoch. V1 limits
are:

| Limit | Value |
|---|---:|
| Encoded gRPC message | 70 KiB |
| Body chunk | 64 KiB |
| Request body | 1 MiB |
| Response body | 8 MiB |
| Headers | 32 |
| Header name | 64 bytes |
| Header value | 8 KiB |
| Aggregate headers | 32 KiB |
| Capability entries | 3 |
| Capability name | 32 bytes |
| In-flight requests per installation/connection | 32 |
| In-flight requests globally | 1,024 |
| Per-request queued data | 8 chunks and 512 KiB |
| Per-connection queued data | 4 MiB |
| Handshake | 10 seconds |
| Request lifetime | required, at most 120 seconds |
| Heartbeat / disconnect | 15 / 30 seconds |

Peers apply the encoded gRPC message limit before protobuf unmarshal, then
validate decoded field and count bounds before copying, queueing, or dispatch.
Each request has a bounded queue. A slow request is cancelled when its queue
budget is exhausted; it must not block the receive dispatcher or unrelated
requests. Fair sending prevents one response from starving others. HTTP/2 flow
control alone is not the application backpressure contract.

The public relay creates the absolute deadline at ingress using the earlier of
its configured request timeout and 120 seconds. Public-client disconnect may
shorten it. Queue time is included. The agent maps it to the upstream request
context. A request transitions through start, strictly sequenced chunks,
end-of-input, response start, strictly sequenced response chunks, and exactly
one terminal outcome. Cancellation is idempotent; frames after terminal do not
change canonical state.

### Reconnect, retry, and privacy

Connection loss cancels every in-flight request. Reconnection uses bounded
exponential backoff with full jitter and a new connection UUIDv7. Neither peer
resumes or automatically replays a partial request, including one whose
canonical commit result is ambiguous. A caller retry must reuse ADR 0010's
idempotency key so the Memory Node returns the prior receipt rather than
duplicating a write.

Relay and node-agent logs contain only closed error codes and aggregate service
metadata. They exclude bodies, header values, assertions, OAuth subjects,
tokens, certificate material, installation/request/trace IDs, and upstream free
text. Metrics use bounded labels and never payload or identity values. Request
capture, gRPC payload tracing, proxy buffering, body spooling, and core dumps
are disabled.

The relay and node agent run as separate Unix users with only their own
credentials. The node agent has no database, Git, shell-execution, or arbitrary
destination authority. The canonical Memory Node LXC is not the public relay
host.

## Deferred identity decision

Before public routing is enabled, a later accepted ADR must define:

- maintained OAuth provider and protected-resource metadata behavior;
- opaque versus JWT access-token validation and revocation;
- exact external-subject binding and canonical schema changes;
- signed assertion serialization, algorithms, body integrity, key
  distribution, replay storage, and normalized path semantics;
- relay request identity representation in status and audit provenance;
- request-local read-only ChatGPT versus read/write Codex tool discovery; and
- generic public URL versus installation-addressed compatibility profiles.

No implementation may fill those gaps with unverified headers, a forwarded
OAuth bearer, direct-private credentials, generic JSON capability metadata, or
caller-selected canonical IDs.

## Consequences

- Node certificate identity and revocation are defined without granting the
  relay memory authority.
- Payloads remain transient and transport reconnect cannot replay writes.
- The additive protobuf update and enrollment primitives can proceed against a
  reviewed contract.
- Public OAuth, signed request identity, Memory Node relay authentication, and
  plugin activation remain deliberately fail closed until their separate ADR.
- Public-host deployment and live ChatGPT/Codex acceptance remain explicit
  operator gates, not claims synthetic tests may make.
