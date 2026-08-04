# Operations

Liveness answers whether a process can serve HTTP. Readiness answers whether it
can perform its intended work. A `200` from `/healthz` does not make a scaffold
or a dependency-failed process ready.

## Current operator surfaces

| Process | Default listener | Liveness | Readiness | Metrics |
|---|---|---|---|---|
| Memory API | `127.0.0.1:8080` | `GET /healthz` returns `200` with the version | `GET /readyz` returns `200` only when PostgreSQL is reachable, the database is at the exact compatible Alembic head, and `vector`, `pg_trgm`, `citext`, and `pgcrypto` are installed; otherwise it returns a sanitized `503` dependency state | `GET /metrics` returns Prometheus text, or `404` when `KIVRA_MEMORY_METRICS_ENABLED=false` |
| Relay scaffold | `127.0.0.1:8090` | `GET /healthz` returns `200` | `GET /readyz` returns `503 not_ready` until the production relay is implemented | `GET /metrics` returns label-free Prometheus service information |
| Node-agent scaffold | `127.0.0.1:8091` | `GET /healthz` returns `200` | `GET /readyz` returns `503 not_enrolled` until enrollment is implemented | `GET /metrics` returns label-free Prometheus service information |
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
[ADR 0006](adr/0006-external-reverse-proxy.md). A future public relay must
expose only its intended client route through the public proxy; do not publish
its operator listener or the canonical Memory Node.

## Local checks

With the processes running on their default listeners:

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --silent --show-error http://127.0.0.1:8080/readyz
curl --fail --silent --show-error http://127.0.0.1:8080/metrics

curl --fail --silent --show-error http://127.0.0.1:8090/healthz
curl --silent --show-error http://127.0.0.1:8090/readyz

curl --fail --silent --show-error http://127.0.0.1:8091/healthz
curl --silent --show-error http://127.0.0.1:8091/readyz
```

The readiness commands intentionally omit `--fail` so their JSON bodies remain
visible while the relay and node-agent are expected to return `503`.

The tunnel has a separate activation and credential boundary; follow the
[Secure MCP Tunnel deployment guide](../deploy/memory-node/tunnel/README.md)
instead of treating its health result as Memory API readiness.

Production runbooks will cover installation, upgrades, credential rotation,
queue diagnosis, archive verification, relay enrollment, and safe shutdown.
