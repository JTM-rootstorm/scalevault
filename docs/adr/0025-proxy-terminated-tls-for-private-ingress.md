# ADR 0025: Proxy-terminated TLS for private ingress

- Status: Accepted
- Date: 2026-08-10
- Amends: ADR 0022, ADR 0023, and ADR 0024
- Amended by: ADR 0026

## Context

ADR 0024 initially required separately authenticated TLS between Nginx Proxy
Manager and the private Codex ingress. That duplicated certificate deployment
on every backend service and defeated the owner's intended centralized
Let's Encrypt termination model.

The Memory LXC is reachable only on the operator's private routed network. NPM
has a LAN/VPN-only access list, one stable backend source address, and no public
route to the LXC. ADR 0018 bearer authentication still applies to every MCP
request and never derives authority from network location.

## Decision

Nginx Proxy Manager terminates the client-facing Let's Encrypt connection. It
forwards to the Codex ingress over HTTP on the exact private LXC address and
port 8443. The ingress carries no TLS certificate or private key and exposes no
public listener.

The plaintext hop is permitted only while all of these controls hold:

- the application binds one exact private address, never a wildcard;
- systemd permits inbound connections only from NPM's exact `/32` or `/128`;
- an independent persistent firewall permits port 8443 only from that same
  exact source;
- NPM's LAN/VPN access list rejects unapproved clients;
- the backend has no public DNS route, NAT, port-forward, or UPnP exposure;
- NPM performs no upstream retry, body logging, caching, compression, or
  response buffering; and
- ADR 0018 authenticates and rechecks each direct-private bearer independently
  of the proxy peer, client address, or any forwarding field.

Uvicorn proxy-header interpretation remains disabled. After the immediate
socket peer, Host, Origin, path, query, method, header, body, and lifetime
checks pass, the dedicated ingress may accept and discard bounded
`Forwarded`, `Via`, `X-Real-IP`, and `X-Forwarded-*` fields emitted by NPM. It
must remove them before bearer authentication and MCP dispatch. Their values
never select a tenant, actor, client, transport, scope, audit identity, URL,
scheme, or destination.

This is a narrow exception to ADR 0022's backend-encryption requirement and
ADR 0023's forwarding-field rejection. It does not authorize any other private
HTTP listener or make forwarding metadata trusted.

Client-side plaintext HTTP receives a fixed content-free rejection at NPM; it
is not redirected. The LXC never redirects and exposes no client-facing
plaintext route.

## Consequences

- Let's Encrypt certificates and keys remain centralized at NPM.
- The private hop carries bearer credentials and MCP request/response payloads
  in plaintext. A compromised private-network device capable of passive
  capture, the router/switch path, NPM, or the LXC host can observe them.
- The exact-source firewall prevents unauthorized connection establishment but
  does not protect against passive packet capture.
- The temporary operator CA and backend leaf created during staging are not
  part of the accepted topology and must be removed after the HTTP listener is
  active.
- Any future exposure beyond this private single-owner network requires a new
  ADR and authenticated backend encryption before activation.
