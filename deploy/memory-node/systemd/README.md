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
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin --gid kivra-memory memory-lifecycle
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin --gid kivra-memory memory-exporter
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin --gid kivra-memory memory-ingress
groupadd --system kivra-sealed
groupadd --system memory-purge
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin --gid memory-purge memory-purge
usermod --append --groups kivra-sealed memory-api
usermod --append --groups kivra-memory,kivra-sealed memory-purge
mountpoint --quiet /mnt/memory
install -d -o root -g root -m 0755 /opt/kivra-memory/app
install -d -o root -g kivra-memory -m 0750 /etc/kivra-memory
install -d -o root -g root -m 0755 /mnt/memory/kivra-memory
install -d -o root -g kivra-memory -m 2750 \
  /mnt/memory/kivra-memory/models
install -d -o memory-node -g kivra-memory -m 0700 \
  /mnt/memory/kivra-memory/node-agent
install -d -o memory-exporter -g kivra-memory -m 0700 \
  /mnt/memory/kivra-memory/archive
install -d -o root -g kivra-sealed -m 2770 \
  /var/lib/kivra-memory-sealed/keys
```

Treat an already-existing account with unexpected UID, GID, shell, home, or
group membership as an installation error; inspect and reconcile it rather than
blindly replacing it. The application tree is root-owned and not writable by a
service account.

Create `memory-api.env`, `memory-worker.env`, `memory-lifecycle-worker.env`, `node-agent.env`, and `tunnel.env` locally under
`/etc/kivra-memory`. Each file must be root-owned and mode `0600`, except the
dedicated lifecycle-worker file described below. Never copy `.env` from a
development checkout. Database passwords remain local deployment secrets and
must not appear in this repository, shell history, or command output. Private
keys and API keys must use systemd credentials rather than environment files.

The Milestone 6 services have separate Unix users and PostgreSQL roles. The
exporter uses `kivra_memory_exporter`. GitHub discovery and validation use
`kivra_memory_ingress`, while the canonical selection transaction uses a
separate local `kivra_memory_api` connection. Never grant canonical event writes
to the ingress role.

### Optional sealed content

Sealed content is disabled by default. Enabling it requires the API drop-in
under `systemd/sealed-content/`, a root-owned mode-`0600` file containing 32 to
128 random bytes at `/etc/kivra-memory/sealed-digest-binding`, and these API
settings:

```text
KIVRA_MEMORY_SEALED_CONTENT_ENABLED=true
KIVRA_MEMORY_SEALED_KEY_PROVIDER_ROOT=/var/lib/kivra-memory-sealed/keys
KIVRA_MEMORY_SEALED_DIGEST_BINDING_CREDENTIAL=/run/credentials/kivra-memory-api.service/sealed-digest-binding
```

The local provider never writes key bytes to PostgreSQL, environment variables,
Git, or `/mnt/memory`. Back up `/var/lib/kivra-memory-sealed/keys` and the
digest-binding credential through a separate restricted key-recovery process.
Restoring only PostgreSQL and the archive does not restore sealed-content
readability. Replacing the binding credential makes existing sealed idempotency
bindings unverifiable and requires a separately reviewed rotation procedure.

Install `memory-sealed-worker.env` as `root:memory-purge` mode `0640`:

```text
KIVRA_MEMORY_PURGE_DATABASE_URL=postgresql+psycopg://kivra_memory_purge:REPLACE_WITH_PERCENT_ENCODED_PASSWORD@127.0.0.1/kivra_memory
KIVRA_MEMORY_PURGE_TENANT_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_PURGE_ACTOR_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_PURGE_CLIENT_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_PURGE_TRANSPORT_BINDING_ID=REPLACE_WITH_UUIDV7
```

Those IDs must identify one unexpired `internal_service` binding with a service
actor, a worker client scoped exactly to `memory.lifecycle.purge`, and the exact
authorized operation `payload_purge_completed`. The worker claims only
`purge_payload` jobs and emits only content-free startup and retry diagnostics.
The authenticated API composition must construct both `SelectionEngine` and
`QueryEngine` through `SealedRuntime`; setting the environment variables alone
does not turn dependency-unavailable MCP executors into a usable sensitivity-4
path.

Install and verify the optional units only after those prerequisites exist:

```sh
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/kivra-memory-sealed-worker.service \
  /etc/systemd/system/kivra-memory-sealed-worker.service
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/sealed-content/kivra-memory-api.service.d/20-sealed-content.conf \
  /etc/systemd/system/kivra-memory-api.service.d/20-sealed-content.conf
systemctl daemon-reload
systemd-analyze verify \
  kivra-memory-api.service \
  kivra-memory-sealed-worker.service
```

### Archive exporter

Install `/etc/kivra-memory/memory-archive-exporter.env` as root-owned mode
`0600`:

```text
KIVRA_MEMORY_ARCHIVE_DATABASE_URL=postgresql+psycopg://kivra_memory_exporter:REPLACE_WITH_PERCENT_ENCODED_PASSWORD@127.0.0.1/kivra_memory
KIVRA_MEMORY_ARCHIVE_TENANT_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_ARCHIVE_TARGET_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_ARCHIVE_REPOSITORY=/mnt/memory/kivra-memory/archive
KIVRA_MEMORY_ARCHIVE_REPOSITORY_REFERENCE=ssh://git@REPLACE_WITH_FORGEJO_HOST/REPLACE_WITH_OWNER/REPLACE_WITH_REPOSITORY.git
KIVRA_MEMORY_ARCHIVE_BRANCH=main
KIVRA_MEMORY_ARCHIVE_SCHEMA_ROOT=/opt/kivra-memory/app/schemas
KIVRA_MEMORY_ARCHIVE_ALLOWED_SIGNERS_FILE=/etc/kivra-memory/archive-allowed-signers
KIVRA_MEMORY_ARCHIVE_KNOWN_HOSTS_FILE=/etc/kivra-memory/archive-known-hosts
KIVRA_MEMORY_ARCHIVE_SIGNER_PRINCIPAL=archive@scalevault
KIVRA_MEMORY_ARCHIVE_AUTHOR_NAME=ScaleVault Archive
KIVRA_MEMORY_ARCHIVE_AUTHOR_EMAIL=archive@scalevault.invalid
```

Install `archive-signing-key` and the repository-scoped `archive-deploy-key` as
root-owned mode-`0600` files named by the unit. Install the allowed-signers and
pinned Forgejo known-hosts files as root-owned mode `0644`. The repository must
be an absolute, clean Git worktree below `/mnt/memory`; global/system Git config,
credential prompts, hooks, and ambient SSH agents are not used.

### GitHub ingress

Install `/etc/kivra-memory/memory-github-ingress.env` as root-owned mode `0600`:

```text
KIVRA_MEMORY_GITHUB_INGRESS_DATABASE_URL=postgresql+psycopg://kivra_memory_ingress:REPLACE_WITH_PERCENT_ENCODED_PASSWORD@127.0.0.1/kivra_memory
KIVRA_MEMORY_GITHUB_COMMAND_DATABASE_URL=postgresql+psycopg://kivra_memory_api:REPLACE_WITH_PERCENT_ENCODED_PASSWORD@127.0.0.1/kivra_memory
KIVRA_MEMORY_GITHUB_TENANT_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_GITHUB_TRANSPORT_BINDING_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_GITHUB_INSTALLATION_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_GITHUB_ACTOR_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_GITHUB_CLIENT_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_GITHUB_REPOSITORY_ID=REPLACE_WITH_NUMERIC_ID
KIVRA_MEMORY_GITHUB_REPOSITORY_OWNER=REPLACE_WITH_OWNER
KIVRA_MEMORY_GITHUB_REPOSITORY_NAME=REPLACE_WITH_REPOSITORY
KIVRA_MEMORY_GITHUB_BRANCH=main
KIVRA_MEMORY_GITHUB_INGRESS_PREFIX=ingress/v2
KIVRA_MEMORY_GITHUB_ALLOWED_SELECTION_BASIS=verified_project_decision
KIVRA_MEMORY_GITHUB_AUTHORITY_CLASS=verified_project_source
KIVRA_MEMORY_GITHUB_EVIDENCE_KIND=project_source
KIVRA_MEMORY_GITHUB_EVIDENCE_TRUST=trusted
KIVRA_MEMORY_GITHUB_PROMOTION_ACTOR_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_GITHUB_PROMOTION_CLIENT_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_GITHUB_PROMOTION_TRANSPORT_BINDING_ID=REPLACE_WITH_UUIDV7
```

The trust-profile fields are operator-owned policy inputs, not claims accepted
from proposal content. The configured basis, authority, evidence kind, and trust
must be reviewed as one policy tuple. Install the fine-grained, repository-only,
read-only token as root-owned mode `0600` at
`/etc/kivra-memory/github-ingress-token`. Webhooks remain disabled; any future
listener must be separately hosted and may only wake this same immutable poller.

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

Candidate expiry is a distinct policy service and must not share the embedding
worker account, environment, model mount, or job dispatcher. Its root-owned
environment file is deliberately readable only by its dedicated service account:

```text
KIVRA_MEMORY_DATABASE_URL=postgresql+psycopg://kivra_memory_policy:REPLACE_WITH_PERCENT_ENCODED_PASSWORD@127.0.0.1/kivra_memory
KIVRA_MEMORY_LIFECYCLE_TENANT_IDS=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_LIFECYCLE_ACTOR_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_LIFECYCLE_CLIENT_ID=REPLACE_WITH_UUIDV7
KIVRA_MEMORY_LIFECYCLE_TRANSPORT_BINDING_ID=REPLACE_WITH_UUIDV7
```

Install it `root:memory-lifecycle` mode `0640`. The listed IDs must already
refer to one unexpired `internal_service` binding in that tenant, with a service
actor and worker client whose client scope is exactly `memory.lifecycle.expire`.
The service supports exactly one tenant per identity; use a separate reviewed
unit configuration before expanding that boundary. It claims only
`expire_candidate` jobs, verifies that binding on every poll, and records only
allowlisted outbox failure codes.

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
file, except use `install -o root -g memory-lifecycle -m 0640` for
`memory-lifecycle-worker.env`. The node-agent file is optional at this
milestone because the service remains disabled. The API file is required before
starting the API; the tunnel file is required only when the separately gated
tunnel is started.

Verify the local boundary before enabling anything:

```sh
stat -c '%U:%G %a %n' \
  /opt/kivra-memory/app \
  /etc/kivra-memory \
  /etc/kivra-memory/memory-api.env \
  /etc/kivra-memory/memory-worker.env \
  /etc/kivra-memory/memory-lifecycle-worker.env \
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
  deploy/memory-node/systemd/kivra-memory-lifecycle-worker.service \
  /etc/systemd/system/kivra-memory-lifecycle-worker.service
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/kivra-memory-archive-exporter.service \
  /etc/systemd/system/kivra-memory-archive-exporter.service
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/kivra-memory-github-ingress.service \
  /etc/systemd/system/kivra-memory-github-ingress.service
install -D -o root -g root -m 0644 \
  deploy/memory-node/postgresql/systemd/postgresql@17-main.service.d/10-kivra-memory-mount.conf \
  /etc/systemd/system/postgresql@17-main.service.d/10-kivra-memory-mount.conf
systemctl daemon-reload
systemd-analyze verify \
  postgresql@17-main.service \
  kivra-memory-api.service \
  kivra-memory-node-agent.service \
  kivra-memory-worker.service \
  kivra-memory-lifecycle-worker.service \
  kivra-memory-archive-exporter.service \
  kivra-memory-github-ingress.service \
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
implemented. The ingress and exporter units remain disabled until their pinned
identities, credentials, clean worktree, database roles, and remote identities
have passed a synthetic acceptance run. The worker
unit remains disabled until its pinned bundle, registry row, tenant
configuration, and live acceptance gate have been verified. The lifecycle worker
remains disabled until its preprovisioned internal-service identity, policy-role
credential, and candidate-expiry acceptance gate have been verified.

The tunnel unit is installed separately and remains disabled until its Platform
tunnel ID, restricted runtime credential, and ChatGPT workspace association are
available. Its MCP target and health UI are both loopback-only; see
`../tunnel/README.md` for the credential boundary and activation checks.

The sealed-content drop-in and purge unit remain uninstalled and disabled when
sealed content is not explicitly enabled. Before activation, provision the
dedicated PostgreSQL role, pinned internal-service identity, separate key
backup, and digest-binding recovery material, then exercise
create/read/hard-forget in a disposable tenant. The key directory is
intentionally independent of the archive/NAS mount.

For exporter activation, verify the `archive_targets` row, clean branch, pinned
Forgejo host key, deploy-key repository scope, allowed signer, signed
fast-forward push, and manifest/checkpoint hash equality. Divergence is a hard
stop; never force-push or rewrite archive history. For ingress activation,
verify the numeric GitHub repository ID, owner/name/default branch, installation
and binding IDs, read-only token scope, both local database logins, and the
promotion service binding. Run a non-sensitive synthetic proposal and the
50-object concurrency gate before enabling the service.
