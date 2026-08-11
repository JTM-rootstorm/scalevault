# ADR 0024: Dedicated private Codex ingress

- Status: Accepted
- Date: 2026-08-10
- Extends: ADR 0006, ADR 0018, ADR 0022, and ADR 0023
- Amends: ADR 0022
- Amended by: ADR 0025

## Context

The canonical Memory API and ChatGPT Secure MCP Tunnel share an intentional
loopback boundary. Publishing that process through the separately managed
reverse proxy would also make its ChatGPT and operator routes reachable and
would combine two credential profiles.

The owner already operates a private-network HTTPS reverse proxy with an
access list limited to LAN/VPN traffic. The canonical LXC is not reachable from
the public internet. The proxy terminates client TLS and forwards through the
isolated private network to the Memory Node. VPN and proxy policy provide
reachability controls only; ADR 0018 remains the application identity.

ADR 0022 prohibited public DNS and any public reverse-proxy route. The existing
shared proxy may bind a public interface and the selected hostname may have
public DNS, but its ScaleVault virtual host rejects non-LAN/VPN sources at the
edge before opening an upstream connection. This ADR narrows the earlier
prohibition accordingly: public MCP access and a publicly reachable backend
remain forbidden, while a content-free edge rejection is allowed.

## Decision

ScaleVault runs a second API process named `kivra-memory-codex-ingress`. It:

- binds one exact private IP literal on TCP port 8443;
- exposes only the direct Streamable HTTP `/mcp` application;
- constructs no ChatGPT runtime or secure-tunnel route;
- exposes no health, readiness, metrics, OAuth, documentation, or operator
  route;
- reuses the canonical `MemoryNodeRuntime`, domain handlers, database, sealed
  content provider, and ADR 0018 request-scoped bearer authentication;
- uses the existing `memory-api` Unix account but a distinct systemd service
  and credential namespace; and
- remains independent of the ChatGPT tunnel service.

The existing canonical API remains loopback-only. Stopping or failing either
process must not stop the other.

### Configuration profile

The production process requires the explicit profile
`codex_private_ingress`. It fails startup unless all of these are valid:

- one non-loopback, non-wildcard, non-global private IPv4 or IPv6 literal;
- exact port 8443;
- one canonical lowercase external DNS hostname without a scheme, port, path,
  query, fragment, wildcard, or user information;
- one or more private trusted-proxy host routes (`/32` or `/128`) containing
  only an immediate proxy socket peer;
- metrics and ChatGPT tunnel support disabled; and
- the client-token pepper loaded only through the ingress service's systemd
  credential path.

When sealed content is enabled, its digest-binding secret is loaded through the
ingress service's own systemd credential path. The ingress uses the same
owner-bound local key store and Unix account as the canonical API. Its atomic
file operations must pass a multi-process concurrency test before that profile
is activated.

Canonical-loopback and Codex-ingress credential paths are not interchangeable.
Private coordinates remain operator-local configuration and must not appear in
repository examples, distributable plugins, logs, or acceptance records.

### HTTP boundary

Before credential lookup, the private boundary requires:

- socket peer membership in the configured trusted-proxy CIDRs;
- exact raw path `/mcp`, an empty query string, and method `GET`, `POST`, or
  `DELETE`;
- exactly one external `Host`;
- zero or one `Origin`, which when present is exactly the HTTPS origin for that
  host; and
- no trusted `Forwarded`, `Via`, `X-Real-IP`, or `X-Forwarded-*` field. ADR
  0025 permits the exact proxy peer's bounded automatically generated fields
  only when the ingress discards them before authentication and dispatch.

Duplicate singleton headers, ambiguous encodings, redirects, and CORS
preflights fail closed. Forwarding fields fail closed unless ADR 0025's exact
discard-only boundary applies. Header count, header bytes, and the 1 MiB
request ceiling remain bounded by ADR 0023. The validated external `Host` and
`Origin` are normalized to the loopback MCP contract before the request reaches
the direct bearer middleware. No network field enters the canonical tenant,
actor, client, transport, scope, or audit identity.

The application, rather than an idle timeout, enforces a 300-second total
lifetime for `GET`/SSE requests and a 30-second total lifetime for `POST` and
`DELETE` requests. Periodic SSE traffic does not extend the limit. An expired
stream closes and reconnects through fresh ADR 0018 authentication, while a
pre-response timeout returns a content-free `504`. The proxy uses compatible
connect, send, and read timeouts, but those idle timers do not replace the
application total-lifetime boundary.

### Proxy and backend trust

The external proxy:

- serves the exact private HTTPS hostname only to its LAN/VPN access list;
- rejects every non-LAN/VPN request before selecting or contacting the
  ScaleVault upstream;
- routes exact `/mcp` only and returns a non-redirecting rejection for every
  other path;
- does not rely on forwarding or real-IP headers for authority; ADR 0025
  permits NPM's generated fields only because the exact-peer ingress discards
  them before authentication and dispatch;
- preserves the single `Authorization` field and required MCP headers;
- performs no upstream retry or failover for POST requests;
- caps and buffers request bodies, disables response buffering for SSE, and
  never spools or logs MCP bodies or authorization values; and
- forwards with HTTP to the exact private backend address and port and has no
  public DNS or NAT exposure.

Client TLS terminates at the separately managed proxy. ADR 0025 replaces the
independently authenticated backend-TLS requirement with an explicitly trusted
private HTTP hop from one exact proxy peer. The proxy and private network remain
live bearer-and-payload-processing trust boundaries.

## Consequences

- ChatGPT Web retains its existing outbound-only, query-only tunnel path.
- Codex devices receive HTTPS through the private proxy but authenticate with
  distinct direct-private bearers on every request.
- The private ingress cannot expose or fall through to ChatGPT or operator
  routes.
- Repository tests can prove configuration and application behavior, but the
  actual proxy access list, firewall, VPN, TLS certificate, NAT state, and
  physical-device identities require dated live evidence.
- External acceptance must prove a non-LAN/VPN request receives only the
  proxy's fixed rejection and cannot elicit an MCP, authentication, operator,
  or backend response.
