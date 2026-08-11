# Threat model

The system will defend against unauthorized clients, stolen device and tunnel
credentials, accidental public proxy exposure, VPN route leakage, malicious
ingress payloads, prompt injection, stale concurrent updates, archive
tampering, private-seed leakage, and host or database loss.

Security work is incomplete until each trust boundary has abuse cases,
mitigations, automated tests, and revocation procedures.

## Private access boundaries

VPN membership supplies reachability, not ScaleVault identity. Every Codex
device still authenticates with its own request-scoped direct-private bearer,
and removing a VPN peer does not replace revoking that bearer. The planned
private HTTPS ingress must reject public routes, wildcard binds, invalid Host
or Origin values, untrusted forwarding headers, redirects, and requests outside
its bounded source and payload policy.

Secure MCP Tunnel is a distinct outbound path to the exact loopback
`/chatgpt/mcp` read surface. Its OpenAI control-plane key and injected
ScaleVault bearer are separate credentials. The tunnel cannot reach the direct
`/mcp` mutation surface, and the OpenAI product remains a live
payload-processing trust boundary. Public relay, OAuth, and installation
routing threats are dormant while ADR 0022 keeps those services unprovisioned.

## Database runtime credentials

Forced row-level security prevents accidental tenant access when the
transaction-local `scalevault.tenant_id` setting is absent or does not match a
row. Runtime roles are non-owners without `BYPASSRLS` or schema-creation rights.

The tenant setting is application-supplied, however, and PostgreSQL custom
settings are not an authentication mechanism. Compromise of a shared service
database credential can therefore select another tenant context allowed to
that service role. Treat such a credential as a service-wide secret, rotate it
on suspected disclosure, and do not describe row-level security as isolation
from a stolen runtime credential. Credential-scoped tenant isolation would
require distinct database roles or an independently authenticated database
context per tenant.
