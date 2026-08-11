# ADR 0022: Private single-owner access topology

- Status: Accepted
- Date: 2026-08-10
- Supersedes: ADR 0020 and ADR 0021
- Extends: ADR 0001, ADR 0006, ADR 0018, and ADR 0019

## Context

ScaleVault is operated for one owner. A stable public relay, public OAuth
facade, generic installation routing, and public plugin distribution add trust
boundaries and operational cost that this deployment does not need. Codex runs
on owner-controlled devices that can join the private network through a
user-managed VPN. ChatGPT Web cannot directly reach a local MCP server, but
OpenAI Secure MCP Tunnel provides an outbound-only path to a private MCP target
without a public ScaleVault listener.

ADRs 0020 and 0021 defined a defensible public-relay design before this
single-owner deployment scope was selected. They remain useful design history,
but they are no longer the active Milestone 9 production architecture.

## Decision

### Active access paths

The production topology has exactly two MCP access paths:

```text
ChatGPT Web
  -> OpenAI-hosted Secure MCP Tunnel endpoint
  -> outbound tunnel-client
  -> http://127.0.0.1:8080/chatgpt/mcp

Owner-controlled Codex device
  -> user-managed VPN or private LAN
  -> private HTTPS ingress
  -> /mcp
```

The canonical Memory Node and PostgreSQL remain private. ScaleVault publishes
no MCP listener, relay route, OAuth metadata, enrollment endpoint, or operator
endpoint to the public internet. Public DNS, NAT forwarding, UPnP mappings, and
public reverse-proxy routes for ScaleVault are forbidden.

### ChatGPT Web through Secure MCP Tunnel

ADR 0019 remains the complete ChatGPT authorization contract. The tunnel
targets only the exact loopback `/chatgpt/mcp` route. That route constructs the
ten read/status tools frozen by ADR 0019 and cannot construct a command
principal or mutation tool. It cannot fall through or redirect to `/mcp`.

The OpenAI tunnel runtime key authenticates `tunnel-client` to the OpenAI
control plane. It is not a ScaleVault identity. A separate protected ADR 0019
`svb1` bearer is injected into discovery and MCP requests and is verified from
PostgreSQL on every request. Neither credential may substitute for the other.

One tunnel identity, injected bearer, client, binding, and installation
represent one intended ChatGPT workspace or private app association. Expanding
that association requires separately provisioned identity or a later reviewed
decision. The tunnel client retains its fixed local target, four-request
concurrency bounds, loopback-only health interface, empty payload log, separate
service user, cleared ambient proxy/header settings, and systemd credential
boundary.

OpenAI and the selected ChatGPT workspace are live payload-processing trust
boundaries. ScaleVault makes no claim that tunnel-carried MCP content is hidden
from the OpenAI product or excluded from normal app-level product logging.

### Codex through private VPN reachability

The VPN supplies reachability only. It never authenticates a ScaleVault user,
selects a tenant or actor, grants a scope, or changes a request's transport
kind. Each Codex host or environment receives its own independently revocable
ADR 0018 direct-private actor, client, binding, and bearer credential. The
Memory Node performs bearer verification, locked active-state rechecks, and
authorization on every request. Removing a device from the VPN does not replace
credential revocation.

Private-network access uses exact HTTPS `/mcp`; plaintext MCP over the LAN or
VPN is not a production profile. Before activation, the ADR 0006 external
reverse-proxy profile must freeze and test:

- one explicit private listener address, never a wildcard;
- firewall policy limited to the VPN/private source ranges controlled by the
  operator;
- an exact private TLS hostname and normal certificate validation;
- exact `Host` validation and `Origin` validation when supplied;
- a fixed trusted-proxy allowlist and rejection of untrusted or duplicate
  forwarding headers;
- request, header, body, concurrency, idle, and total-duration bounds;
- redirect rejection and a single upstream `/mcp` destination; and
- an external proof that no public route, NAT mapping, or proxy host exposes
  the listener.

Optional per-device mTLS may add defense in depth, but it cannot replace the
ADR 0018 bearer identity. Until that ingress contract and implementation pass
review, remote devices must use an authenticated local forward to the existing
loopback listener rather than changing `KIVRA_MEMORY_HOST` or binding to
`0.0.0.0`.

### Deferred relay and public plugin work

The public relay, node-agent enrollment, relay OAuth facade, forwarded relay
identity, public ChatGPT capability profiles, public plugin submission, and
generic third-party installation enrollment are outside v1 and Milestone 9.
No production configuration may start or route to the relay or node-agent.

The relay protobuf, Go services, enrollment primitives, and ADRs 0020 and 0021
are retained temporarily as dormant implementation history. They confer no
supported capability, are not installed by the selected deployment, and must
remain fail-closed. Removing them from the active build and deployment surface
is allowed as a later cleanup slice. Re-enabling any public relay path requires
a new dated product and threat review plus an ADR that supersedes this one.

The active plugin package contains only the private Secure MCP Tunnel profile.
It contains no public relay profile, OAuth flow, registered public app identity,
or submission candidate. Private network coordinates and credentials remain
operator configuration and never enter distributable artifacts.

The optional GitHub proposal ingress remains a separate, disabled-by-default
transport governed by ADRs 0004 and 0016. It is not a ChatGPT MCP path and is
not required by Milestone 9. Enabling it still requires its own current
account-side capability probe and explicit per-action approval.

## Milestone 9 acceptance boundary

Milestone 9 now closes private access rather than creating a public service:

1. A fresh supported ChatGPT Web chat reads through Secure MCP Tunnel and the
   exact ADR 0019 tool registry.
2. ChatGPT cannot discover or invoke nomination or mutation tools.
3. At least two VPN-connected Codex devices read and write through private
   HTTPS with distinct direct-private audit identities.
4. VPN reachability without a valid bearer fails closed.
5. Revoking one Codex credential blocks its next request without disrupting the
   other device or ChatGPT tunnel identity.
6. The private ingress passes host, origin, forwarding-header, TLS, bounds, and
   no-public-route checks.
7. Relay, node-agent, OAuth, public-plugin, and submission surfaces remain
   disabled and unprovisioned.

## Consequences

- ChatGPT retains private Web access without a public ScaleVault endpoint.
- Codex devices use the simpler direct-private identity path after joining the
  owner's VPN.
- The VPN and tunnel solve reachability but do not become canonical identity
  authorities.
- Public relay multi-tenancy, OAuth, domain ownership, abuse controls, and app
  review are removed from the active delivery schedule.
- A reviewed private HTTPS ingress is now the main unfinished Milestone 9
  implementation slice.
