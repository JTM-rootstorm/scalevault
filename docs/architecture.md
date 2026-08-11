# Architecture

ScaleVault has one canonical private Memory Node. PostgreSQL owns semantic
state. ChatGPT Web reaches the query-only route through outbound Secure MCP
Tunnel, while owner-controlled Codex devices use distinct direct-private
identities after joining the private network through the operator's VPN.
GitHub ingress may carry explicitly approved proposals but is not an alternate
memory store. Forgejo is a deterministic recovery archive written by one
logical exporter.

Shared contracts are versioned and reviewed centrally. All write transports
must converge on the same policy and concurrency-safe domain command layer.
The private GitHub proposal repository evolves independently; its current and
legacy contract boundary is tracked in
[GitHub ingress compatibility](ingress-compatibility.md) and must be re-audited
before importer work resumes.

The production Memory API listener and PostgreSQL destination remain restricted
to loopback or an approved local Unix socket. Secure MCP Tunnel reaches the API
through that local boundary. A VPN/private-LAN HTTPS ingress for Codex is the
remaining Milestone 9 transport slice and is not yet implemented. Until its
[ADR 0022](adr/0022-private-single-owner-access-topology.md) controls are
implemented, devices must use an authenticated local forward. The canonical
node must never be directly reachable from the public internet.

The public relay and node-agent are superseded, dormant implementation history.
They are not installed, started, or supported by the selected v1 topology.
