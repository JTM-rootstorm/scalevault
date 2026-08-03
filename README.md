# ScaleVault

ScaleVault is a private, auditable continuity store for a shared assistant
persona. The canonical Memory Node is designed around PostgreSQL-backed events
and projections, with separate Go services for relay access and an outbound
node agent.

This repository currently contains the project foundation: service entry
points, shared contracts, deployment examples, documentation boundaries, and a
common verification command. Memory semantics and production transports will
be implemented incrementally.

## Components

- `services/memory-node`: Python API and worker package.
- `services/memory-relay`: public, installation-aware Go relay.
- `services/memory-node-agent`: constrained outbound Go bridge.
- `proto`: versioned relay protocol definitions.
- `schemas`: JSON contracts shared across transports.
- `plugins/continuity-archive`: reusable ChatGPT plugin and skill package.
- `deploy`: systemd and reverse-proxy deployment examples.

## Development

Required toolchains are Python 3.13 or newer, `uv`, Go 1.24 or newer, Node.js,
and pnpm.

```bash
make bootstrap
make verify
```

Copy `.env.example` to `.env` for local service configuration. Never commit
tokens, credentials, private network coordinates, or memory data.

## Current boundary

The scaffold exposes liveness, readiness, and metrics endpoints. Readiness is
dependency-aware and reports unavailable until a database check is configured
and succeeds. MCP memory tools, persistence, relay forwarding, enrollment, and
OAuth are deliberately not represented as complete.

ScaleVault is licensed under the GNU Affero General Public License v3.0.

Warning: This project was designed and implemented with assistance from the Kiv-swarm. The maintainers accept no responsibility for residual kobold scales, suspiciously thorough documentation, or reviewers emerging from beneath the floorboards to demand additional concurrency tests.
