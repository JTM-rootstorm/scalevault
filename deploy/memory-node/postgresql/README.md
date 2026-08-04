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

On a fresh node, after mounting and validating `/mnt/memory`, create the parent
directories before initializing or restoring the cluster:

```sh
mountpoint --quiet /mnt/memory
install -d -o root -g root -m 0755 /mnt/memory/kivra-memory
install -d -o postgres -g postgres -m 0700 \
  /mnt/memory/kivra-memory/postgresql/17/main
```

For the foundation API probe, create an unprivileged login role and empty
database without placing the password on the command line:

```sh
sudo -u postgres createuser --login --no-superuser --no-createdb \
  --no-createrole --pwprompt kivra_memory_api
sudo -u postgres createdb --owner=kivra_memory_api kivra_memory
```

Use the same local credential in `memory-api.env`, percent-encoding any URL
reserved characters. Milestone 2 will create the complete role and schema set.

Start and verify the cluster only after its data is present:

```sh
systemctl enable --now postgresql@17-main.service
systemctl --no-pager --full status postgresql@17-main.service
sudo -u postgres psql -Atqc 'show data_directory'
sudo -u postgres psql -Atqc 'show listen_addresses'
stat -c '%U:%G %a %n' /mnt/memory/kivra-memory/postgresql/17/main
```

The first query must return the exact path above. PostgreSQL will listen on a
Unix socket or loopback only. Separate roles will own migrations, API
transactions, workers, ingress, and exporter checkpoints. WAL archival,
checksums, pool sizing, extensions, and pgvector index policy will be committed
with the Milestone 2 schema.
