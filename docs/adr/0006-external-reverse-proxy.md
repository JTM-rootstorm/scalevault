# ADR 0006: External reverse-proxy ownership

- Status: Accepted
- Date: 2026-08-03

## Context

The original implementation plan placed Nginx in the canonical Memory Node
LXC. The deployed environment already has a separately managed
Nginx Proxy Manager instance for TLS termination and reverse-proxy policy.
Installing another proxy in the Memory Node would duplicate configuration and
expand the canonical data host's package and network surface.

Private Secure MCP Tunnel access does not require an inbound proxy: the tunnel
client and Memory API communicate over loopback. Development clients can also
connect directly to loopback or through an explicit local forward.

## Decision

ScaleVault does not install or manage Nginx inside the canonical Memory Node
LXC. Application and operator listeners default to loopback. The OpenAI tunnel
client connects to the Memory API over loopback, while public plugin traffic
continues to terminate at the separate generic relay defined by ADR 0001.

If a future private-LAN HTTPS profile is enabled, the external Nginx Proxy
Manager instance owns TLS termination, request limits, and routing. That profile
requires an explicit, narrowly scoped non-loopback listener configuration and
must not make the canonical LXC directly reachable from the public internet.
Development does not require an in-container reverse proxy.

## Consequences

- The Memory Node package list and deployment artifacts contain no Nginx
  service or configuration.
- Loopback-only defaults remain a security boundary, not merely a development
  convenience.
- External proxy configuration and credentials are administered outside this
  repository and outside the canonical LXC.
- A future private-LAN listener needs a reviewed configuration change with
  origin, host, authentication, and exposure controls.
- The plan's in-LXC Nginx and development-proxy tasks are superseded by this
  environment-specific decision.
