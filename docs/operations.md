# Operations

Liveness answers whether a process can serve HTTP. Readiness answers whether it
can perform its intended work. A `200` from `/healthz` does not make a scaffold
or a dependency-failed process ready.

## Current operator surfaces

| Process | Default listener | Liveness | Readiness | Metrics |
|---|---|---|---|---|
| Memory API | `127.0.0.1:8080` | `GET /healthz` returns `200` with the version | `GET /readyz` returns `200` only when PostgreSQL is reachable, the database is at the exact compatible Alembic head, and `vector`, `pg_trgm`, `citext`, and `pgcrypto` are installed; otherwise it returns a sanitized `503` dependency state | `GET /metrics` returns Prometheus text, or `404` when `KIVRA_MEMORY_METRICS_ENABLED=false` |
| Secure MCP Tunnel | `127.0.0.1:8081` | `GET /healthz` is owned by `tunnel-client` | `GET /readyz` is owned by `tunnel-client` and depends on tunnel control-plane and MCP initialization | Not owned by ScaleVault |

The Memory API also mounts Streamable HTTP MCP at `/mcp`. Operator endpoints
are not MCP tools. A future authenticated `/admin/status` is not implemented.
The Memory API readiness body reports only fixed `database`, `migrations`, and
`extensions` states. It never includes connection strings, migration error
details, or database exception text. The Secure MCP Tunnel systemd unit waits
for this complete API readiness result before it starts.

Production configuration enforces a loopback-only Memory API listener and a
local PostgreSQL destination. Do not set `KIVRA_MEMORY_HOST` to a private
interface to make an external proxy work. A future private-LAN profile requires
the separate reviewed configuration described by
[ADR 0022](adr/0022-private-single-owner-access-topology.md). Until then, use an
authenticated local forward over the VPN. Do not publish an operator listener,
the canonical Memory Node, or any superseded relay service.

The relay and node-agent binaries are dormant implementation history. They are
not current operator surfaces and must not be installed, enabled, or granted
credentials in the selected topology.

## Local checks

With the processes running on their default listeners:

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --silent --show-error http://127.0.0.1:8080/readyz
curl --fail --silent --show-error http://127.0.0.1:8080/metrics

```

The tunnel has a separate activation and credential boundary; follow the
[Secure MCP Tunnel deployment guide](../deploy/memory-node/tunnel/README.md)
instead of treating its health result as Memory API readiness.

Production runbooks cover installation, upgrades, credential rotation, queue
diagnosis, archive verification, tunnel recovery, and safe shutdown. Private
VPN ingress activation remains pending its ADR 0022 implementation slice.
