# ScaleVault

ScaleVault is a private, auditable continuity store for a shared assistant
persona. The canonical Memory Node is designed around PostgreSQL-backed events
and projections, with separate Go services for relay access and an outbound
node agent.

This repository contains the project foundation plus the canonical PostgreSQL
schema, immutable event engine, deterministic projection rebuild, and
database-role bootstrap and validation suite. MCP memory tools, retrieval, and
production mutation workers are implemented incrementally in later milestones.

## Components

- `services/memory-node`: Python API and worker package.
- `services/memory-relay`: public, installation-aware Go relay.
- `services/memory-node-agent`: constrained outbound Go bridge.
- `proto`: versioned relay protocol definitions.
- `schemas`: JSON contracts shared across transports.
- `plugins/continuity-archive`: reusable ChatGPT plugin and skill package.
- `deploy`: systemd and development examples plus external-proxy boundary docs.

## Development

Required toolchains are Python 3.13 or newer, `uv`, Go 1.24 or newer, Node.js,
pnpm 10.15.0, and Docker with Compose support. Contract generation additionally
requires Protocol Buffers compiler 31.1; its pinned Go generators use the Go
1.25 toolchain through Go's isolated tool module. The versions observed on the
Debian 13 Memory Node are recorded in the [dated capability
probe](docs/capability-probe-2026-08-03.md).

```bash
make bootstrap
make verify
```

`make verify` is the non-destructive common gate. With PostgreSQL 17-or-newer
server binaries on `PATH`, `make test-database` runs the real-database lane in
an isolated temporary cluster and removes it afterward. Release acceptance uses
`make test-database-required`, which fails instead of skipping when PostgreSQL
or any required extension is unavailable.

For interactive development, start the checked-in PostgreSQL service and then
run the Memory API:

```bash
cp .env.example .env
docker compose -f deploy/development/compose.yaml up -d --wait
uv run --locked kivra-memory-api
```

The checked-in `.env.example` and Compose service share this loopback-only
development credential:

```text
postgresql+psycopg://kivra_memory:change-me@127.0.0.1/kivra_memory
```

In another shell, check the operator endpoints:

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --fail --silent --show-error http://127.0.0.1:8080/readyz
curl --fail --silent --show-error http://127.0.0.1:8080/metrics
```

Stop the API with `Ctrl-C`, then stop PostgreSQL while preserving its development
volume:

```bash
docker compose -f deploy/development/compose.yaml down
```

Use `docker compose -f deploy/development/compose.yaml down --volumes` only when
you intentionally want to delete the disposable development database. Never
commit `.env`, tokens, credentials, private network coordinates, or memory data.
The [development PostgreSQL guide](deploy/development/README.md) describes the
persistent interactive volume and isolated test-cluster boundary.

See [Operations](docs/operations.md) for endpoint semantics and
[Shared contract workflow](docs/shared-contracts.md) before changing protobuf or
JSON contracts.

## Current boundary

The API exposes liveness, schema- and extension-aware readiness, metrics, and
the echo surface. The canonical database contracts and event replay engine are
present, while user-facing MCP memory tools, retrieval, relay forwarding,
enrollment, and OAuth are deliberately not represented as complete.

Milestone status is tracked in the
[dated Milestone 2 acceptance checklist](docs/milestone-2-acceptance-2026-08-07.md).

ScaleVault is licensed under the GNU Affero General Public License v3.0.

Warning: This project was designed and implemented with assistance from the Kiv-swarm. The maintainers accept no responsibility for residual kobold scales, suspiciously thorough documentation, or reviewers emerging from beneath the floorboards to demand additional concurrency tests.
