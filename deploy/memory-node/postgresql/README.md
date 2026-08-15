# PostgreSQL deployment

The canonical PostgreSQL 17 cluster stores its data on the dedicated persistent
mount, not on the LXC root filesystem:

```text
/mnt/memory/kivra-memory/postgresql/17/main
```

The directory must be owned by `postgres:postgres` with mode `0700`. Refuse to
create or initialize it until `mountpoint --quiet /mnt/memory` succeeds. The
NFS or other remote-storage export must provide PostgreSQL-compatible locking
and durability semantics; verify the export ACL, mount options, snapshots, and
restore behavior before storing canonical memory data.

Set the following value in `/etc/postgresql/17/main/postgresql.conf`:

```conf
data_directory = '/mnt/memory/kivra-memory/postgresql/17/main'
```

For an existing cluster, stop PostgreSQL and migrate the data with the normal
PostgreSQL backup/restore or verified file-copy procedure before changing
`data_directory`. Do not initialize a second cluster over existing data.

## Mount-gated service

Install the committed drop-in so the Debian cluster cannot start unless
`/mnt/memory` is an actual mount point:

```sh
install -D -o root -g root -m 0644 \
  deploy/memory-node/postgresql/systemd/postgresql@17-main.service.d/10-kivra-memory-mount.conf \
  /etc/systemd/system/postgresql@17-main.service.d/10-kivra-memory-mount.conf
systemctl daemon-reload
systemd-analyze verify postgresql@17-main.service
```

The instance drop-in runs `pg_ctlcluster` as `postgres:postgres`. This is
required when the persistent export root-squashes UID 0: the Debian wrapper
checks the configured data directory before starting the server, and a
root-run wrapper cannot traverse that otherwise valid directory. PostgreSQL
itself, its PID file, log, and normal start/stop/reload paths remain owned by
the dedicated cluster identity.

On a fresh node, after mounting and validating `/mnt/memory`, create the parent
directories before initializing or restoring the cluster:

```sh
mountpoint --quiet /mnt/memory
install -d -o root -g root -m 0755 /mnt/memory/kivra-memory
install -d -o postgres -g postgres -m 0700 \
  /mnt/memory/kivra-memory/postgresql/17/main
```

## Database roles and ownership

ScaleVault uses a non-login object owner and separate login roles for migrations,
the API, workers, GitHub ingress, and archive export. The committed role bootstrap
also upgrades the Milestone 1 layout in which `kivra_memory_api` owned the
database. It reassigns that role's existing objects and makes the API a
non-owner with `NOBYPASSRLS`.

On a new cluster, create the empty database with the temporary PostgreSQL
bootstrap owner. Do not put a password on a command line:

```sh
runuser -u postgres -- createdb kivra_memory
```

Install the operator-owned migration prerequisites before running Alembic. The
application migrations verify these extensions but never create or own them:

```sh
runuser -u postgres -- psql --dbname=kivra_memory \
  --command='CREATE EXTENSION IF NOT EXISTS citext' \
  --command='CREATE EXTENSION IF NOT EXISTS pg_trgm' \
  --command='CREATE EXTENSION IF NOT EXISTS pgcrypto' \
  --command='CREATE EXTENSION IF NOT EXISTS vector'
```

The bootstrap requires both an explicit connection database and the same exact
database name in `expected_database`. It exits before `BEGIN` if either is
missing or they differ:

```sh
runuser -u postgres -- psql --dbname=kivra_memory \
  --set=expected_database=kivra_memory \
  --file=deploy/memory-node/postgresql/bootstrap_roles.sql
```

The bootstrap is idempotent. Run it once before Alembic so the migrator can
create objects as `kivra_memory_owner`, and again after every migration so new
objects receive the reviewed privilege matrix. It performs these ownership and
security transitions:

- `kivra_memory_owner` is `NOLOGIN` and owns the database, `public` schema,
  migration functions, and application tables.
- `kivra_memory_migrator` is a non-superuser login with `NOINHERIT`; it may
  `SET ROLE kivra_memory_owner`, and that role is the database-specific default.
- `kivra_memory_api`, `kivra_memory_worker`, `kivra_memory_ingress`, and
  `kivra_memory_exporter` are non-owner logins with `NOBYPASSRLS` and no schema
  creation or role-management authority.
- `PUBLIC` cannot connect, create objects in `public`, or execute ScaleVault's
  trigger functions directly. Operator-owned extension functions retain their
  extension-defined privileges.

The application privilege matrix is deliberately asymmetric:

| Role | Reads | Writes |
| --- | --- | --- |
| API | Canonical domain state, ingress proposals, and readiness revision | Event counter, immutable events/receipts, sessions, outbox, canonical ingress results |
| Worker | Events, domain state, projections, embedding/outbox state | Projections, content-key metadata, embedding registry, outbox leases |
| Ingress | Installation/binding context and ingress proposals | Discover proposals and record validation, rejection, or quarantine state only |
| Exporter | Events and deterministic archive projection inputs | Append-only archive checkpoints |

Runtime roles never receive `CREATE`, `TRIGGER`, table ownership, event update
or event delete privileges. Forced row-level security still restricts every
tenant-owned table by the transaction-local `scalevault.tenant_id` setting.

The SQL creates missing login roles without passwords and preserves passwords
on existing roles. Provision or rotate each credential interactively, through
an approved secret manager, or through systemd credentials. For example:

```sh
runuser -u postgres -- psql --command='\password kivra_memory_api'
```

Do not use `ALTER ROLE ... PASSWORD '...'` in a shell argument, checked-in SQL,
or deployment log. Store each service's distinct database URL in its protected
environment/credential file, percent-encoding URL-reserved password characters.

The guarded migration entrypoint accepts either `kivra_memory_migrator` or the
local `postgres` operator over a Unix socket, then explicitly assumes
`kivra_memory_owner`. It rejects other login and transport combinations. The
migrator's database-specific default role also selects the non-login owner;
operators should verify `SELECT current_user` reports `kivra_memory_owner`
before applying a revision. Installing extensions remains a `postgres`
operator action and is not part of Alembic or the application role bootstrap.

## Ownership cutover

Treat the first upgrade of an existing Milestone 1 database as a maintenance
cutover. Before starting, confirm the exact database, mounted data directory,
current owner, backup freshness, and restore procedure without displaying any
credential values:

```sh
mountpoint --quiet /mnt/memory
runuser -u postgres -- psql --dbname=kivra_memory --no-psqlrc \
  --command="SELECT current_database(), current_setting('data_directory')" \
  --command='SELECT datname, pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()'
runuser -u postgres -- psql --dbname=kivra_memory --no-psqlrc \
  --command="SELECT rolname, rolcanlogin, rolvaliduntil IS NOT NULL AS has_expiry FROM pg_authid WHERE rolname LIKE 'kivra_memory_%' ORDER BY rolname"
```

The role query intentionally reports neither password hashes nor credential
values. Verify the latest encrypted backup and a recent restore test in the
backup system's own audit interface before proceeding.

During the cutover, stop database-writing services, apply the role bootstrap,
run the guarded injected-connection Alembic deployment, and reapply the
bootstrap so every newly created object receives reviewed grants:

```sh
systemctl stop kivra-memory-tunnel.service kivra-memory-api.service
runuser -u postgres -- psql --dbname=kivra_memory --no-psqlrc \
  --set=expected_database=kivra_memory \
  --file=deploy/memory-node/postgresql/bootstrap_roles.sql
runuser -u postgres -- env \
  KIVRA_MEMORY_MIGRATION_DATABASE_URL=postgresql+psycopg:///kivra_memory \
  KIVRA_MEMORY_EXPECTED_DATABASE=kivra_memory \
  make migrate-database
runuser -u postgres -- psql --dbname=kivra_memory --no-psqlrc \
  --set=expected_database=kivra_memory \
  --file=deploy/memory-node/postgresql/bootstrap_roles.sql
```

Before restarting services, verify the revision, ownership, forced RLS, and
that the migrator's database-local default role is the non-login owner:

```sh
runuser -u postgres -- psql --dbname=kivra_memory --no-psqlrc \
  --command='TABLE alembic_version' \
  --command="SELECT DISTINCT pg_get_userbyid(relowner) FROM pg_class JOIN pg_namespace ON pg_namespace.oid = relnamespace WHERE nspname = 'public' AND relkind IN ('r','p','S') ORDER BY 1" \
  --command="SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class JOIN pg_namespace ON pg_namespace.oid = relnamespace WHERE nspname = 'public' AND relrowsecurity ORDER BY relname"
systemctl start kivra-memory-api.service
systemctl start kivra-memory-tunnel.service
```

If migration or verification fails, keep writers stopped. Restore the verified
backup or correct the failed step under operator review; do not repair ownership
or grants ad hoc while services are running.

Start and verify the cluster only after its data is present:

```sh
systemctl enable --now postgresql@17-main.service
systemctl --no-pager --full status postgresql@17-main.service
runuser -u postgres -- psql -Atqc 'show data_directory'
runuser -u postgres -- psql -Atqc 'show listen_addresses'
stat -c '%U:%G %a %n' /mnt/memory/kivra-memory/postgresql/17/main
```

The first query must return the exact path above. PostgreSQL will listen on a
Unix socket or loopback only. WAL archival, checksums, pool sizing, and pgvector
index policy remain separate operator-reviewed deployment concerns.
