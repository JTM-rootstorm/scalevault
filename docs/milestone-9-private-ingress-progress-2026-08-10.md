# Milestone 9 private-ingress progress

Milestone 9 was rescoped by ADR 0022 and ADR 0024 to keep ChatGPT Web on the
outbound Secure MCP Tunnel and give owner-controlled Codex devices a separate
direct-private HTTPS ingress. This record is a progress checkpoint, not
Milestone 9 acceptance.

## Repository evidence

- The dedicated direct-only ingress, process-profile separation, hard request
  lifetimes, deployment profile, and private topology ADR are committed through
  `b03be89`.
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
- `make verify` passed on the development host: 1,203 Python tests passed and
  172 PostgreSQL tests were skipped because that host lacks the required
  `vector` extension. Ruff, mypy, Go vet/tests/build determinism, protobuf
  determinism, JSON schemas, and plugin checks also passed.
- The authoritative unprivileged LXC PostgreSQL 17 lane passed all 187
  integration tests with the required extension gate enabled and zero skips.

## Sanitized live evidence

- A new immutable release was installed without deleting the prior release.
- The canonical Memory API remained loopback-only and the Secure MCP Tunnel
  remained active throughout deployment.
- The initial ingress staging listener used TLS on one exact private address
  and port 8443 with no wildcard listener. ADR 0025 subsequently selected
  centralized Let's Encrypt termination at NPM and an exact-source private
  HTTP backend; that live listener replacement is pending this checkpoint.
- The service is pinned to one exact proxy host route in both systemd IP policy
  and the application configuration.
- An independent persistent firewall permits port 8443 from that proxy route
  and drops other sources. A direct LAN probe incremented only the drop
  counter, while a proxy-originated probe incremented only the allow counter.
- The temporary backend certificate and operator CA are staging artifacts, not
  the accepted topology. They remain protected until the HTTP replacement is
  active and then must be removed. Application credentials remain only in
  protected live configuration.
- The canonical API, ChatGPT tunnel, and private ingress were all active after
  the isolated ingress restart.

## Open activation gate

The separately managed reverse proxy has the new backend port, but the live
backend still uses the superseded staging protocol. Current credential-free
probes return `502` over HTTPS, redirect plaintext HTTP, and do not enforce the
exact path at the edge.

Milestone acceptance remains open until the proxy administrator:

1. switches the ingress and NPM backend to HTTP on the exact private address
   and port while retaining the exact NPM `/32` and LXC firewall gate;
2. keeps Let's Encrypt TLS and its private key only at NPM;
3. disables client plaintext redirects in favor of a fixed content-free
   rejection;
4. routes exact raw `/mcp` only and rejects queries, aliases, and other paths
   before opening an upstream connection;
5. proves NPM-generated forwarding fields are bounded and discarded before
   application authentication, and never become canonical authority;
6. preserves the LAN/VPN access-list rejection before upstream selection;
7. disables upstream retry, response buffering, compression, access logging,
   and request-body spooling; and
8. inspects complete `nginx -T` real-IP and Access List ordering, then proves
   spoofed forwarding headers cannot turn an external source into a LAN/VPN
   source; and
9. passes live authenticated initialize/read/mutation, revocation, SSE
   reconnect, no-retry, log-canary, and external-source probes.

The generated proxy configuration must be inspected after the UI saves it.
Repository templates and an edge `200`/`401` alone are not evidence that the
proxy preserved these boundaries.
