# ADR 0023: Bounded loopback MCP HTTP boundary

- Status: Accepted
- Date: 2026-08-10
- Extends: ADR 0018, ADR 0019, and ADR 0022

## Context

ADR 0022 keeps the canonical Memory API on loopback while a separately managed
private HTTPS boundary will serve VPN-connected Codex devices. ChatGPT Web must
continue to use the exact loopback `/chatgpt/mcp` route. Relaxing the API bind
or trusting proxy-supplied client metadata would combine those trust paths.

The MCP SDK currently supplies DNS-rebinding protection and a request-body
limit by default, but relying on dependency defaults makes the production
boundary vulnerable to future drift. Uvicorn also enables proxy-header
processing by default for loopback peers. A local forward or proxy would then
make untrusted forwarding headers appear to come from a trusted peer.

## Decision

The canonical Memory API remains bound to an exact loopback address in
production. ScaleVault explicitly configures every production MCP server with:

- DNS-rebinding protection enabled;
- allowed `Host` values of `127.0.0.1:*`, `localhost:*`, and `[::1]:*` only;
- allowed `Origin` values using `http` and those same loopback hosts only; and
- a 1 MiB maximum encoded POST body.

The application adds a transport-neutral header boundary around each MCP
application. After the route-specific bearer authenticator succeeds, the
boundary:

- accepts at most 64 headers and 16 KiB across raw header names and values;
- requires exactly one `Host`;
- rejects duplicate `Origin`, `Content-Type`, `Content-Length`,
  `Transfer-Encoding`, `MCP-Protocol-Version`, or `MCP-Session-Id` fields;
- rejects simultaneous `Content-Length` and `Transfer-Encoding`;
- rejects `Forwarded`, `Via`, `X-Real-IP`, and every `X-Forwarded-*` field; and
- returns a fixed payload-free error without logging header values.

The direct and ChatGPT authenticators continue to require exactly one
`Authorization` field before this boundary runs. Uvicorn runs with proxy-header
processing and server-version headers disabled. ScaleVault never derives
canonical identity, scheme, source policy, tenant, or authority from peer
addresses or forwarding headers.

The future private HTTPS proxy must validate the external TLS hostname, `Host`,
optional `Origin`, source range, path, and limits before rewriting the upstream
request to the loopback MCP contract. It must route only exact `/mcp`, strip
forwarding metadata, disable redirects, and never route `/chatgpt/mcp` or
operator endpoints. The proxy and any authenticated persistent forward are
live deployment trust boundaries; repository tests cannot prove that they are
not publicly reachable.

## Consequences

- ChatGPT tunnel behavior and the loopback-safe API default remain unchanged.
- A proxy cannot make caller-supplied forwarding metadata authoritative.
- Oversized authenticated JSON-RPC envelopes are rejected before MCP parsing or
  tool dispatch.
- The externally managed proxy must normalize its upstream `Host` and validate
  any external `Origin` before stripping it.
- Private ingress activation still requires live proxy, firewall, VPN, TLS, and
  external no-public-route evidence.
