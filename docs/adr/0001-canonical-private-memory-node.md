# ADR 0001: Canonical private Memory Node

- Status: Accepted
- Date: 2026-08-03

## Context

ScaleVault supports multiple access paths, including direct private clients,
an outbound node agent connected to a generic relay, and proposal ingress.
Allowing those paths to become independent memory authorities would create
inconsistent policy, identity, and concurrency behavior. Publishing the
canonical LXC directly would also expose the most sensitive service boundary.

## Decision

ScaleVault has one canonical private Memory Node. It is the only semantic
authority for durable memory operations, regardless of the transport used to
request them.

The canonical LXC is not exposed directly to the public internet. Public plugin
traffic terminates at the generic relay and reaches the Memory Node through the
outbound node-agent path. The relay remains a transport and does not become a
second Memory Node.

## Consequences

- All transports must converge on the canonical Memory Node's policy and domain
  command handling.
- Public endpoints can be operated without publishing the LXC's address or
  accepting public inbound connections on it.
- Loss of the canonical Memory Node makes semantic operations unavailable;
  transports cannot promote cached or queued data into authoritative state.
- The relay must remain incapable of independently interpreting or mutating
  memory state.
