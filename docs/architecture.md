# Architecture

ScaleVault has one canonical private Memory Node and multiple transport
profiles. PostgreSQL owns semantic state. The public relay and GitHub ingress
carry requests or proposals but are not alternate memory stores. Forgejo is a
deterministic recovery archive written by one logical exporter.

Shared contracts are versioned and reviewed centrally. All write transports
must converge on the same policy and concurrency-safe domain command layer.

The production Memory API listener and PostgreSQL destination are restricted to
loopback or an approved local Unix socket. Secure MCP Tunnel and node-agent
traffic reaches the API through that local boundary. A non-loopback private-LAN
profile is not currently implemented and requires the reviewed controls in
[ADR 0006](adr/0006-external-reverse-proxy.md); the canonical node must never be
made directly reachable from the public internet.
