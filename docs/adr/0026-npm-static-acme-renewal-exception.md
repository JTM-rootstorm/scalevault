# ADR 0026: NPM static ACME renewal exception

- Status: Accepted
- Date: 2026-08-10
- Extends: ADR 0006
- Amends: ADR 0022, ADR 0024, and ADR 0025

## Context

The private Codex ingress uses an existing Let's Encrypt certificate terminated
by Nginx Proxy Manager. NPM's Let's Encrypt host template installs an ACME
challenge handler that supports HTTP-01. Its generated configuration contains
both a precedence location, `location ^~ /.well-known/acme-challenge/`, and an
exact-directory rejection, `location = /.well-known/acme-challenge/`. The
precedence location explicitly bypasses the Proxy Host Access List and outranks
ScaleVault's regex application-path rejection.

The prior ADRs correctly prohibit public MCP, operator, authentication, and
backend routes, but their unqualified statements that every other HTTP path is
rejected do not describe this NPM-managed static renewal path.

## Decision

The NPM edge may expose the exact prefix `/.well-known/acme-challenge/` without
the LAN/VPN Access List only for NPM's static Let's Encrypt challenge handler,
subject to all of these constraints:

- `location ^~ /.well-known/acme-challenge/` serves challenge files from NPM's
  dedicated static ACME webroot with authentication disabled and `allow all`;
- `location = /.well-known/acme-challenge/` returns `404` for the exact
  challenge directory;
- neither location contains `proxy_pass`, an upstream, an application rewrite,
  bearer handling, dynamic execution, a directory listing, or a Memory Node
  route;
- a valid provisioned challenge token may return `200` from the static webroot;
- missing and unprovisioned token paths return `404` and never contact the
  Memory LXC;
- ScaleVault clients never send Authorization or MCP payloads to this prefix;
- NPM's generated configuration proves the prefix is static-only after every
  NPM or certificate-management upgrade; live Memory backend counters prove
  only that a specific probe did not contact the Memory backend; and
- every non-ACME application path other than exact `/mcp` remains a fixed,
  non-redirecting, pre-upstream rejection.

The public challenge token and its request metadata are certificate-protocol
data, not ScaleVault memory or authorization data. This exception does not make
the Memory Node, MCP endpoint, health surfaces, or NPM-to-LXC hop public.

If certificate renewal moves to a mode that does not install the static
HTTP-01 location, the exception becomes dormant; it does not authorize a new
public path.

## Consequences

- Public-route proofs distinguish the static ACME renewal prefix from
  ScaleVault application routes.
- Client HTTP outside the ACME prefix still receives no redirect and never
  reaches the Memory backend.
- Acceptance evidence records the exact installed NPM and Nginx versions and,
  where available, the immutable NPM container image digest because routing
  safety depends on generated configuration ordering.
