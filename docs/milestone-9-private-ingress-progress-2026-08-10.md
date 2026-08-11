# Milestone 9 private-ingress progress

Milestone 9 was rescoped by ADR 0022 and ADR 0024 to keep ChatGPT Web on the
outbound Secure MCP Tunnel and give owner-controlled Codex devices a separate
direct-private HTTPS ingress. This record is a progress checkpoint, not
Milestone 9 acceptance.

## Repository evidence

- The dedicated direct-only ingress, process-profile separation, hard request
  lifetimes, deployment profile, and private topology ADR are committed through
  `ab68907`.
- The ingress exposes only exact `/mcp`, accepts only Streamable HTTP `GET`,
  `POST`, and `DELETE`, and retains ADR 0018 bearer authentication on every
  request.
- After exact proxy-peer validation, the application bounds and discards NPM
  forwarding metadata before authentication. It rejects untrusted proxy peers,
  ambiguous authority headers, oversized requests, aliases, redirects, and
  non-HTTP ASGI scopes before canonical dispatch.
- Spawned-process key-provider tests cover provision/provision,
  provision/destroy, get/destroy, and interrupted-publication races without
  material resurrection or temporary-file residue.
- `make verify` passed on the development host: 1,206 Python tests passed and
  172 PostgreSQL tests were skipped because that host lacks the required
  `vector` extension. Ruff, mypy, Go vet/tests/build determinism, protobuf
  determinism, JSON schemas, and plugin checks also passed.
- The authoritative unprivileged LXC PostgreSQL 17 lane passed all 187
  integration tests with the required extension gate enabled and zero skips.

## Sanitized live evidence

- Immutable release `48a6e4f` was installed without deleting the prior release.
- The canonical Memory API remained loopback-only and the Secure MCP Tunnel
  remained active throughout deployment.
- The ingress now serves HTTP on one exact private address and port 8443 with
  no wildcard listener. Client-facing Let's Encrypt termination remains at NPM.
- The service is pinned to one exact proxy host route in both systemd IP policy
  and the application configuration.
- An independent persistent firewall permits port 8443 from that proxy route
  and drops other sources. A direct LAN probe incremented only the drop
  counter, while a proxy-originated probe incremented only the allow counter.
- The five temporary backend certificate and operator-CA artifacts were
  permanently removed after the HTTP listener became active. Application
  credentials remain only in protected live configuration.
- The canonical API, ChatGPT tunnel, and private ingress were all active after
  the isolated ingress restart.
- After the NPM upstream changed to HTTP, credential-free HTTPS requests to
  exact `/mcp` returned the expected application `401`, proving the approved
  NPM route reaches the private HTTP listener without forwarding credentials.
- NPM now owns one `/mcp` Custom Location so its existing source-CIDR Access
  List remains the single source of truth. A non-conflicting regex catch-all
  rejects every other path.
- Client HTTP `/mcp`, operator paths, trailing slashes, query strings, and
  unsupported methods returned fixed `404` or `405` responses without
  redirects. The backend firewall counter remained unchanged across those
  probes, then increased only for exact HTTPS `/mcp` as it returned `401`.
- The canonical API, ChatGPT tunnel, and private ingress remained active, and
  tunnel readiness remained `ready`, after the edge changes.

## Open activation gate

The separately managed reverse proxy now reaches the HTTP backend and its
credential-free route guards pass. No bearer was sent before those edge gates
closed.

Milestone acceptance remains open until the proxy administrator:

1. verifies the generated Custom Location contains the source-CIDR-only Access
   List, no Basic-auth integration or Authorization clearing, exactly one
   private backend `proxy_pass`, and the reviewed buffering, timeout, logging,
   retry, and compression controls;
2. proves NPM-generated forwarding fields are bounded and discarded before
   application authentication, and never become canonical authority;
3. inspects complete `nginx -T` real-IP and Access List ordering, then proves
   spoofed forwarding headers cannot turn an external source into a LAN/VPN
   source; and
4. passes live authenticated initialize/read/mutation, revocation, SSE
   reconnect, no-retry, log-canary, and external-source probes.

The generated proxy configuration must be inspected after the UI saves it.
Repository templates and an edge `200`/`401` alone are not evidence that the
proxy preserved these boundaries.
