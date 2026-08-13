# Operations

Liveness answers whether a process can serve HTTP. Readiness answers whether it
can perform its intended work. A `200` from `/healthz` does not make a scaffold
or a dependency-failed process ready.

## Current operator surfaces

| Process | Default listener | Liveness | Readiness | Metrics |
|---|---|---|---|---|
| Memory API | `127.0.0.1:8080` | `GET /healthz` returns `200` with the version | `GET /readyz` returns `200` only when PostgreSQL is reachable, the database is at the exact compatible Alembic head, and `vector`, `pg_trgm`, `citext`, and `pgcrypto` are installed; otherwise it returns a sanitized `503` dependency state | `GET /metrics` returns Prometheus text, or `404` when `KIVRA_MEMORY_METRICS_ENABLED=false` |
| Database metrics exporter | `127.0.0.1:9098` | `kivra_memory_database_collector_up` | Each 30-second collection has a hard 10-second timeout; failure clears database-derived samples | `GET /metrics` exposes only fixed-shape aggregates from the dedicated observability function |
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
curl --fail --silent --show-error http://127.0.0.1:9098/metrics
```

The tunnel has a separate activation and credential boundary; follow the
[Secure MCP Tunnel deployment guide](../deploy/memory-node/tunnel/README.md)
instead of treating its health result as Memory API readiness.

## Operating posture

Normal operation has exactly one canonical PostgreSQL cluster. Backups,
monitoring, and recovery readers cannot mutate semantic state. The Forgejo
exporter remains disabled for Milestone 10; no provider restore, continuation,
or exporter-append claim is part of the milestone. Treat retrieved memory,
ingress proposals, alert annotations, archive files, and recovery objects as
untrusted data.

Use these stop conditions in every procedure:

- stop and preserve content-free evidence on signed-history divergence, an
  unknown signer, rollback against an external anchor, a missing WAL segment,
  or a recovery destination that is not disposable;
- stop if a command, log, metric, alert, or evidence artifact exposes a memory
  statement, evidence, proposal body, authorization value, database URL, key,
  credential, or private network coordinate;
- stop startup when dependencies, installation binding, migration
  compatibility, key-destruction state, or credential posture are unknown;
- never rewrite a signed recovery source, delete a base, WAL/history object,
  restore point, or hold under the Milestone 10 no-prune posture, or overlay an
  active database to make a drill pass.

## Operator checks

Run local HTTP checks only on the canonical node. Store output in a protected
operator session, not in shell history or a repository artifact:

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --silent --show-error http://127.0.0.1:8080/readyz
curl --fail --silent --show-error http://127.0.0.1:8080/metrics
systemctl --no-pager --failed
```

Database-backed metrics use the `kivra_memory_metrics` login and its SET-only
`kivra_memory_observability` capability. Neither role can select application
tables; the capability can execute only the reviewed aggregate function.
Prometheus scrapes the dedicated `scalevault-database-metrics` job on
loopback port 9098. Do not point it at a private interface or reuse an API
database credential.

PostgreSQL host availability is supplied separately by the checked-in
`scalevault-postgresql` scrape job at exactly `127.0.0.1:9187`. Keep that
exporter loopback-only; it does not replace the payload-blind ScaleVault
aggregate exporter or authorize broader database telemetry.

Generate a protected tenant-scoped operator report through the systemd-bound
runner, where `<report-id>` is a bounded non-sensitive local label:

```bash
systemctl start 'kivra-memory-operator-report@<report-id>.service'
```

The unit supplies the dedicated `kivra_memory_operator_report_login` database
credential and UUIDv7 tenant scope from separate systemd credentials and
creates `/var/lib/kivra-memory/operator-reports/<report-id>.json` as a new
root-only file. It does not use an ambient database URL or stdout. The report
may contain protected identifiers and stays inside the root-local boundary.
Backup and recovery sections deliberately report `status_artifact_required`;
review their separate bounded status artifacts. Reduce any accepted findings
to the evidence boundary below rather than copying the report.

Operational logs and alerts have a 30-day maximum; content-free recovery and
acceptance reports may be retained for at most 400 days. Both classes also
require operator-chosen byte caps, and the earlier age/capacity bound wins.
Until the installed caps are selected and verified, retention activation
remains pending rather than accepted. External alert delivery is not required
for M10; local rule evaluation and visible collector/rule health remain the
acceptance boundary.

## Evidence boundary

Operational records may include release and migration revisions, safe backup
object identifiers, source-head and manifest digests, target time or LSN,
elapsed time, aggregate counts and digests, fixed result codes, credential
reissue posture, write-disable confirmation, and cleanup confirmation. They
must not include payloads, private coordinates, database URLs, decrypted
objects, key material, bearer values, raw exception text, or unbounded
identifiers.

For cross-process canaries, list the exact root-owned regular mode-`0400` or
mode-`0600` operational captures as absolute paths, one per line, in a
root-owned mode-`0600` list. Put only synthetic canaries, one per line, in a
separate root-owned mode-`0600` file, then run:

```bash
kivra-memory-scan-operational-canaries \
  --artifact-list /absolute/root-owned-mode-0600-list \
  --canary-file /absolute/root-owned-mode-0600-canaries
```

The only accepted output is fixed JSON containing `ok`,
`result=clean|match|incomplete`, and bounded `bytes_scanned`, `inputs_scanned`,
and `matches` counts. Exit zero is reserved for `clean`. A `match` or
`incomplete` result fails closed; neither matched bytes nor paths may enter
evidence.

The [runbook index](runbooks/README.md) covers backup and WAL response, safe
shutdown/startup, upgrade/rollback, queue diagnosis, incident and alert
response, provider-independent recovery, NPM drift, and drill cleanup. Future
Forgejo divergence/recovery guidance is retained but is not an M10 procedure.
Credential rotation is separate because each active authority has different
revocation semantics.
