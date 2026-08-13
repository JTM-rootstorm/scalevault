# Safe shutdown and startup

## Shutdown order

Stop external reachability before processes that can commit work, then stop
background writers and the database:

```bash
systemctl stop kivra-memory-codex-ingress.service
systemctl stop kivra-memory-tunnel.service
systemctl stop kivra-memory-github-ingress.service
systemctl stop kivra-memory-sealed-worker.service
systemctl stop kivra-memory-lifecycle-worker.service
systemctl stop kivra-memory-worker.service
systemctl stop kivra-memory-metrics-exporter.service
systemctl stop kivra-memory-api.service
systemctl stop postgresql@17-main.service
```

Keep optional/disabled services disabled. In particular, the Forgejo archive
exporter is excluded from M10 and must already be disabled; stop and investigate
if it is unexpectedly active rather than treating it as part of the normal M10
sequence. Confirm no ScaleVault writer remains, there is no listener on
canonical or private-ingress ports, and PostgreSQL stopped cleanly. Confirm no
operator-report instance or backup/verification job is active before stopping
PostgreSQL or changing mounts. If a stop times out, preserve bounded status
before escalating; do not kill PostgreSQL or a worker during a commit without
determining state.

## Startup preflight

Before starting PostgreSQL, confirm exact mounts, ownership, release,
configuration, migration compatibility, recovery state, secret delivery, and
backup freshness. Stop if `recovery.signal` or unexpected recovery artifacts
exist, destruction state is unresolved, the database appears rolled back, or
credentials require reissue.

## Startup order

1. Start `postgresql@17-main.service`; verify local socket access, extensions,
   exact migration head, archive health, and durability settings.
2. Start the canonical API and require both `/healthz` and `/readyz` locally.
3. After migration `0011_observability_aggregates` and both least-privilege role
   pairs pass, start the loopback metrics exporter. Confirm it binds only
   `127.0.0.1:9098` and its collector state is current. Do not run a protected
   operator report until the exact tenant scope is reviewed.
4. Start only enabled workers, one class at a time. Confirm bounded queue
   progress and no competing leases.
5. Leave every archive exporter disabled. Forgejo provider operation,
   continuation, and exporter append require a future separately authorized
   procedure.
6. Start optional GitHub ingress only if its installation and provider
   credentials were explicitly reviewed.
7. Start the Secure MCP Tunnel and require its readiness result.
8. Start the direct-private Codex ingress last; verify the exact listener,
   firewall, NPM generated configuration, and rejection boundary.

After each stage, stop on readiness failure, unknown identity, canary leakage,
or unexpected writes. Do not enable all units as a bulk recovery shortcut.
