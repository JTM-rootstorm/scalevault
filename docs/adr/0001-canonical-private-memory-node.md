# ADR 0001: Canonical private Memory Node

- Status: Accepted
- Date: 2026-08-03
- Amended by: ADR 0022

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

The canonical LXC is not exposed directly to the public internet. This ADR
originally routed public plugin traffic through a generic relay and outbound
node agent, with the relay remaining transport-only. ADR 0022 supersedes that
clause: the active v1 deployment uses a private ChatGPT tunnel and
VPN-reachable direct Codex paths while preserving this ADR's canonical-node
boundary.

## Consequences

- All transports must converge on the canonical Memory Node's policy and domain
  command handling.
- Private transports operate without accepting public inbound connections on
  the LXC.
- Loss of the canonical Memory Node makes semantic operations unavailable;
  transports cannot promote cached or queued data into authoritative state.
- Any future transport must remain incapable of independently interpreting or
  mutating memory state.
