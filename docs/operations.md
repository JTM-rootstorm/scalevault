# Operations

Liveness answers whether a process can serve HTTP. Readiness answers whether it
can perform its intended work. A `200` from `/healthz` does not make a scaffold
or a dependency-failed process ready.

## Current operator surfaces

| Process | Default listener | Liveness | Readiness | Metrics |
|---|---|---|---|---|
| Memory API | `127.0.0.1:8080` | `GET /healthz` returns `200` with the version | `GET /readyz` returns `200` only when PostgreSQL is reachable, the database is at the exact compatible Alembic head, and `vector`, `pg_trgm`, `citext`, and `pgcrypto` are installed; otherwise it returns a sanitized `503` dependency state | `GET /metrics` returns Prometheus text, or `404` when `KIVRA_MEMORY_METRICS_ENABLED=false` |
| Codex private ingress | exact private address, port `8443` | Not exposed | Not exposed; exact `/mcp` requests require a direct-private bearer | Not exposed |
| Secure MCP Tunnel | `127.0.0.1:8081` | `GET /healthz` is owned by `tunnel-client` | `GET /readyz` is owned by `tunnel-client` and depends on tunnel control-plane and MCP initialization | Not owned by ScaleVault |

The Memory API also mounts Streamable HTTP MCP at `/mcp`. Operator endpoints
are not MCP tools. A future authenticated `/admin/status` is not implemented.
The Memory API readiness body reports only fixed `database`, `migrations`, and
`extensions` states. It never includes connection strings, migration error
details, or database exception text. The Secure MCP Tunnel systemd unit waits
for this complete API readiness result before it starts.

Production configuration enforces a loopback-only canonical Memory API listener
and a local PostgreSQL destination. Do not set `KIVRA_MEMORY_HOST` to a private
interface to make an external proxy work. The accepted private-LAN Codex path is
a separate direct-private service behind the exact NPM HTTPS `/mcp` route; its
backend is one firewall-bounded HTTP listener on the exact private address and
port 8443. It does not expose canonical health, readiness, metrics, or operator
routes. Follow the
[private-ingress deployment guide](../deploy/memory-node/private-ingress/README.md)
and [NPM drift runbook](runbooks/npm-drift.md). Do not publish an operator
listener, the canonical Memory Node, or any superseded relay service.

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

## Operating posture

Normal operation has exactly one canonical PostgreSQL cluster and one logical
Forgejo archive writer. Backups, monitoring, and recovery readers cannot mutate
semantic state. Treat retrieved memory, ingress proposals, alert annotations,
archive files, and recovery objects as untrusted data.

Use these stop conditions in every procedure:

- stop and preserve content-free evidence on archive divergence, an unknown
  signer or host key, rollback against an external anchor, a missing WAL
  segment, or a recovery destination that is not disposable;
- stop if a command, log, metric, alert, or evidence artifact exposes a memory
  statement, evidence, proposal body, authorization value, database URL, key,
  credential, or private network coordinate;
- stop startup when dependencies, installation binding, migration
  compatibility, key-destruction state, or credential posture are unknown;
- never force-push, rewrite either archive copy, prune the last complete
  recovery chain, or overlay an active database to make a drill pass.

## Operator checks

Run local HTTP checks only on the canonical node. Store output in a protected
operator session, not in shell history or a repository artifact:

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --silent --show-error http://127.0.0.1:8080/readyz
curl --fail --silent --show-error http://127.0.0.1:8080/metrics
systemctl --no-pager --failed
```

The root-local `kivra-memory-operator-report` command emits a tenant-scoped,
metadata-only report. It may contain protected identifiers and therefore stays
in the root-local operator boundary. Backup and recovery sections deliberately
report `status_artifact_required`; ingest the separate bounded backup/recovery
status artifacts during operator review. The report must not be copied into a
public issue or acceptance record without reducing it to the evidence boundary
below.

## Evidence boundary

Operational records may include release and migration revisions, safe backup
object identifiers, source-head and manifest digests, target time or LSN,
elapsed time, aggregate counts and digests, fixed result codes, credential
reissue posture, write-disable confirmation, and cleanup confirmation. They
must not include payloads, private coordinates, database URLs, decrypted
objects, key material, bearer values, raw exception text, or unbounded
identifiers.

The [runbook index](runbooks/README.md) covers backup and WAL response, safe
shutdown/startup, upgrade/rollback, queue diagnosis, archive divergence,
incident and alert response, recovery, NPM drift, and drill cleanup. Credential
rotation is a separate procedure because each provider has different
revocation semantics.
