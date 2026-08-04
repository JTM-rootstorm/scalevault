# Milestone 1 acceptance checklist

- Review date: 2026-08-03 (America/Chicago)
- Status: Complete

This checklist distinguishes repository inspection, workstation integration
evidence, and live Debian Memory Node evidence. The presence of a scaffold or
test is not recorded as a successful run without the evidence below.

## Status vocabulary

- **Repository evidence:** the required source, configuration, or test is
  present in the tree.
- **Dated evidence:** a prior acceptance record verifies a bounded probe; rerun
  it when the integrated implementation changes.
- **Deferred:** the component intentionally has no runnable Milestone 1 service
  and is not included in startup acceptance.

## Task checklist

| Requirement | Status | Evidence or remaining check |
|---|---|---|
| Python, Go, and plugin skeletons | Repository evidence | `services/memory-node`, `services/memory-relay`, `services/memory-node-agent`, and `plugins/continuity-archive` contain runnable or checked package foundations. |
| Locked dependencies and lint, format, type, and test lanes | Verified | `make verify` checked the Python and Go module locks, then ran every language-specific lane. The plugin lock also passed a frozen offline pnpm install during implementation. |
| Shared protobuf and JSON contract workflow | Verified | Pinned generation produced byte-identical outputs twice and matched the checked-in bindings. Five schemas, all local references, formats, and representative fixtures passed. |
| Initial systemd and development deployment foundation | Verified | API, node-agent, tunnel, relay, PostgreSQL mount gating, and interactive development PostgreSQL artifacts are present. The API and tunnel completed live systemd startup acceptance. Worker, ingress, and exporter units remain correctly deferred until runnable entry points exist. |
| Typed environment configuration with startup validation | Verified | Tests reject invalid values, remote production database destinations, non-loopback production binds, and secret-bearing configuration failures without printing their inputs. |
| Health, readiness, and metrics behavior | Verified | Python and Go endpoint tests passed. Live API health, database readiness, and metrics returned success over loopback. |
| Disposable PostgreSQL test environment | Verified | The workstation lane created and removed run-scoped PostgreSQL clusters. A separate exact temporary live-node database loaded pgvector 0.8.0 on PostgreSQL 17.10 and was removed immediately afterward. |
| Common validation entry point | Verified | `make verify` passed on the integrated code at `dec7059`. |

## Exit criteria

### Common verification gate

The integrated code at `dec7059` passed:

```bash
make verify
```

The run used Python 3.14.6, Go 1.26.4, `libprotoc 31.1`, and pnpm 10.15.0. It
reported 53 Python tests passed and one pgvector availability test skipped on
the workstation's PostgreSQL 18 installation. Go formatting, vetting, tests,
and byte-identical builds passed. Deterministic protobuf generation, five JSON
schemas and fixtures, Biome formatting/linting, TypeScript checking, and plugin
tests also passed.

### Disposable database lane

The workstation lane completed with one readiness-lifecycle pass and one
pgvector availability skip because that PostgreSQL 18 installation lacks the
extension:

```bash
make test-database
```

Both temporary clusters were removed. The live Debian acceptance then created
the exact temporary database `scalevault_m1_acceptance_20260803`, loaded
pgvector 0.8.0 under PostgreSQL 17.10, and dropped it. A final catalog check
confirmed that the temporary database no longer existed.

### Reproducible relay and node-agent builds

The CGO-disabled relay and node-agent were each built twice with trimmed paths,
VCS stamping disabled, and an empty build ID. Both byte comparisons passed.
The resulting binaries were installed on the live node; the node-agent remains
disabled pending enrollment.

### Readiness fails closed

Repository tests cover missing and unavailable database states and passed in
`make verify`. Production validation also used a sentinel password to prove
that configuration failures print only a sanitized message and exit status.

### Debian systemd startup

The live Debian 13 LXC reported 4 CPUs and 8 GiB RAM. PostgreSQL 17.10 uses
`/mnt/memory/kivra-memory/postgresql/17/main` on the NFSv4 mount, and the exact
committed systemd mount drop-in is active. Native unit verification passed.

The locked Python environment, deterministic Go binaries, API/node-agent units,
and tunnel startup-order fix were installed under their documented paths. A
cold `systemctl start kivra-memory-tunnel.service` pulled in the API dependency,
waited for loopback health, and completed with:

- PostgreSQL, Memory API, and tunnel all `active/running` with zero restarts;
- Memory API `/healthz`, `/readyz`, and `/metrics` successful;
- tunnel `/healthz` reporting `live` and `/readyz` reporting `ready`;
- only `127.0.0.1:8080` and `127.0.0.1:8081` listening for these services;
- API systemd exposure score `4.3 OK`; and
- PostgreSQL, API, node-agent, and tunnel still disabled at boot, preserving the
  existing operator activation policy.

The node-agent remains disabled until relay enrollment exists. Worker, ingress,
and exporter services are deferred until runnable entry points and their
least-privilege service definitions are committed.

The NFS export is mounted with `hard`, NFSv4.2, and `sec=sys`. The operator has
accepted its permissions within the controlled hardware and service boundary,
and encrypted backups are copied offsite. ADR 0007 records that durable storage
decision. Runtime credentials and encryption/signing keys remain outside the
NAS dataset.
