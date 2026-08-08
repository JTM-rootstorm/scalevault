# Memory Node units

These units target the canonical Debian 13 LXC. Install the application under
`/opt/kivra-memory/app`, place service environment files under
`/etc/kivra-memory`, and keep persistent database and node-agent state below
`/mnt/memory/kivra-memory`. The units refuse to start without that mount.

## Accounts and directories

Create only the accounts needed by the units that exist today:

```sh
groupadd --system kivra-memory
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin --gid kivra-memory memory-api
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin --gid kivra-memory memory-node
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin --gid kivra-memory memory-tunnel
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin --gid kivra-memory memory-worker
mountpoint --quiet /mnt/memory
install -d -o root -g root -m 0755 /opt/kivra-memory/app
install -d -o root -g root -m 0750 /etc/kivra-memory
install -d -o root -g root -m 0755 /mnt/memory/kivra-memory
install -d -o root -g kivra-memory -m 2750 \
  /mnt/memory/kivra-memory/models
install -d -o memory-node -g kivra-memory -m 0700 \
  /mnt/memory/kivra-memory/node-agent
```

Treat an already-existing account with unexpected UID, GID, shell, home, or
group membership as an installation error; inspect and reconcile it rather than
blindly replacing it. The application tree is root-owned and not writable by a
service account.

Create `memory-api.env`, `memory-worker.env`, `node-agent.env`, and `tunnel.env` locally under
`/etc/kivra-memory`. Each file must be `root:root` mode `0600`, even when it
currently contains only nonsecret coordinates. Never copy `.env` from a
development checkout. Database passwords remain local deployment secrets and
must not appear in this repository, shell history, or command output. Private
keys and API keys must use systemd credentials rather than environment files.

The required API file sets a production database URL and normally retains the
loopback listener:

```text
KIVRA_MEMORY_DATABASE_URL=postgresql+psycopg://kivra_memory_api:REPLACE_WITH_PERCENT_ENCODED_PASSWORD@127.0.0.1/kivra_memory
KIVRA_MEMORY_HOST=127.0.0.1
KIVRA_MEMORY_PORT=8080
KIVRA_MEMORY_METRICS_ENABLED=true
```

The embedding worker has a separate root-owned mode-0600 environment file. It
contains only its local worker database URL and an explicit comma-separated
allowlist of tenant UUIDs; model paths cannot be supplied by jobs:

```text
KIVRA_MEMORY_DATABASE_URL=postgresql+psycopg://kivra_memory_worker:REPLACE_WITH_PERCENT_ENCODED_PASSWORD@127.0.0.1/kivra_memory
KIVRA_MEMORY_WORKER_TENANT_IDS=REPLACE_WITH_UUIDV7
```

The worker verifies digest-addressed model bundles below
`/mnt/memory/kivra-memory/models`, never downloads model material, and refuses
to start if the network-share mount or approved bundle is unavailable. Its
query-embedding socket is mode `0660` below a mode-`0750` systemd runtime
directory owned by `memory-worker:kivra-memory`. This permits the `memory-api`
account, whose primary group is `kivra-memory`, to request bounded local query
embeddings without importing ONNX Runtime or reading model files.

Prepare a bundle only from artifacts already present on the operator host. The
helper does not download anything; it refuses symlinked inputs, duplicate
sources, an existing destination, and unrecorded files. It writes the four
artifacts plus a canonical manifest into a directory named for the manifest
SHA-256:

```sh
UV_CACHE_DIR=.cache/uv uv run --locked python scripts/prepare_embedding_bundle.py \
  --model-root /mnt/memory/kivra-memory/models \
  --model /path/to/local/model.onnx \
  --tokenizer /path/to/local/tokenizer.json \
  --config /path/to/local/config.json \
  --license /path/to/local/LICENSE \
  --onnxruntime-version 1.28.0 \
  --export-tool REPLACE_WITH_EXPORT_TOOL \
  --export-version REPLACE_WITH_EXPORT_VERSION
```

The single line printed on success is the `artifact_sha256` that must be used
by the corresponding embedding-model registry row. Record the actual export
tool and version; do not substitute illustrative values.

Use `install -o root -g root -m 0600` when placing each completed environment
file. The node-agent file is optional at this milestone because the service
remains disabled. The API file is required before starting the API; the tunnel
file is required only when the separately gated tunnel is started.

Verify the local boundary before enabling anything:

```sh
stat -c '%U:%G %a %n' \
  /opt/kivra-memory/app \
  /etc/kivra-memory \
  /etc/kivra-memory/memory-api.env \
  /etc/kivra-memory/memory-worker.env \
  /mnt/memory/kivra-memory/models \
  /mnt/memory/kivra-memory/node-agent
```

## Network boundary

The accepted production profile binds the API to loopback. Production startup
rejects a non-loopback `KIVRA_MEMORY_HOST`; keep the default value shown above.
Secure MCP Tunnel and node-agent traffic reaches the API over loopback, and
development clients use loopback or an explicit local forward.

There is intentionally no Nginx unit or configuration in this LXC. The Secure
MCP Tunnel and node-agent connect to the loopback API and require no inbound
public listener. [ADR 0006](../../../docs/adr/0006-external-reverse-proxy.md)
assigns any future private-LAN HTTPS profile to the separately managed reverse
proxy, but enabling that profile requires an explicit reviewed application
configuration mode and exposure controls. Do not change the API bind address
merely to make remote access convenient.

## Install and verify

Install the implemented units and the PostgreSQL mount drop-in:

```sh
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/kivra-memory-api.service \
  /etc/systemd/system/kivra-memory-api.service
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/kivra-memory-node-agent.service \
  /etc/systemd/system/kivra-memory-node-agent.service
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/kivra-memory-tunnel.service \
  /etc/systemd/system/kivra-memory-tunnel.service
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/kivra-memory-worker.service \
  /etc/systemd/system/kivra-memory-worker.service
install -D -o root -g root -m 0644 \
  deploy/memory-node/postgresql/systemd/postgresql@17-main.service.d/10-kivra-memory-mount.conf \
  /etc/systemd/system/postgresql@17-main.service.d/10-kivra-memory-mount.conf
systemctl daemon-reload
systemd-analyze verify \
  postgresql@17-main.service \
  kivra-memory-api.service \
  kivra-memory-node-agent.service \
  kivra-memory-worker.service \
  kivra-memory-tunnel.service
```

Start only PostgreSQL and the API for the Milestone 1 foundation:

```sh
mountpoint --quiet /mnt/memory
systemctl enable --now postgresql@17-main.service
systemctl enable --now kivra-memory-api.service
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --fail --silent --show-error http://127.0.0.1:8080/readyz
systemctl is-enabled kivra-memory-node-agent.service
systemctl is-enabled kivra-memory-tunnel.service
```

The readiness request must succeed only after the configured database is
reachable. The last two commands should report `disabled` until their separate
enrollment and workspace prerequisites are satisfied.

## Deferred services

The API unit starts the Debian PostgreSQL 17 cluster dependency. The node-agent
unit is installed but should remain disabled until relay enrollment is
implemented. Ingress, exporter, and timer units will be added with their runnable
entry points so deployment never advertises an unimplemented service. The worker
unit remains disabled until its pinned bundle, registry row, tenant
configuration, and live acceptance gate have been verified.

The tunnel unit is installed separately and remains disabled until its Platform
tunnel ID, restricted runtime credential, and ChatGPT workspace association are
available. Its MCP target and health UI are both loopback-only; see
`../tunnel/README.md` for the credential boundary and activation checks.
