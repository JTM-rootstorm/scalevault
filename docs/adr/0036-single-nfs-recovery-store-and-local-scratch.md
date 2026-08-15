# ADR 0036: Single NFS recovery store and local scratch

- Status: Accepted
- Date: 2026-08-15
- Supersedes: None
- Amends: ADR 0007, ADR 0027, and ADR 0033

## Context

The selected Memory Node has exactly one operator-provided NFS mount:
`/mnt/memory`. Canonical PostgreSQL data and the locally accepted encrypted
PostgreSQL recovery chain must use that mount. Creating additional NFS mounts
for plaintext staging or recovery drills would imply isolation and operational
dependencies that the selected host does not provide.

The operator also performs nightly NAS backups and may protect data through PBS
and Backblaze. Those arrangements are managed outside ScaleVault. Their
configuration cannot be inferred from local directory layout, and repository or
installed-system evidence does not establish that such copies exist, are fresh,
or have passed a restore.

## Decision

### Installed storage topology

The sole NFS mount is exactly `/mnt/memory`. Canonical PostgreSQL `PGDATA`
remains unchanged at:

`/mnt/memory/kivra-memory/postgresql/17/main`

The encrypted PostgreSQL PITR store is:

`/mnt/memory/kivra-memory/backups/postgresql-pitr`

It contains the encrypted base-backup, WAL, timeline-history, manifest, index,
and completion objects governed by ADRs 0027 and 0035. The store is durable only
when `/mnt/memory` is mounted; services fail closed rather than falling back to
the local root filesystem.

Plaintext backup staging is local scratch at:

`/var/lib/kivra-memory/backup-staging`

It is private, bounded, and removed after successful publication or failed
work. Plaintext is never accepted as a durable backup, and the staging path is
not a recovery copy.

On the isolated recovery host, decrypted restore material is rooted at:

`/var/lib/kivra-memory/recovery`

That root is local, disposable plaintext workspace. It must not be on the
routine Memory Node, must never overlay canonical `PGDATA`, and must be cleaned
and independently checked after the drill.

### Authority, custody, and failure domains

Directory ownership and service permissions separate write scope among
canonical PostgreSQL, the encrypted recovery-store producer, verification, and
local scratch. Directory separation does not create a storage failure domain.
Canonical `PGDATA` and the encrypted PostgreSQL PITR store share one NFS mount,
NAS, dataset, and capacity pool. A mount outage, dataset loss, NAS failure, or
pool exhaustion can affect both.

Capacity is therefore evaluated as one pool. Backup admission, no-prune
inventory validation, and capacity alerts must account for the combined use of
canonical PostgreSQL data and the accumulating encrypted recovery chain. Space
pressure fails closed and does not authorize deletion.

The PostgreSQL-aware recovery contract is unchanged: daily verified physical
base backups, continuous encrypted WAL, authenticated manifests and bindings,
isolated PITR, and independently supplied recovery private identity remain
required. The private recovery identity remains absent from the routine Memory
Node and from `/mnt/memory`.

Nightly NAS backups, PBS protection, and Backblaze transfer, retention,
freshness, retrieval, and restore testing are operator-managed. ScaleVault may
describe its encrypted objects as suitable inputs to those systems, but it must
not claim that any external or independent copy exists, is current, or has been
restored without separate operator evidence.

ADR 0035 remains unchanged. Its zero-deletion authority, exact
`no_prune_dependency_watermark_absent` result, inventory validation, and
requirement for a later accepted ADR before any pruning continue to apply.

## Consequences

- The deployed topology needs one NFS mount, not separate staging or recovery
  mounts.
- Local scratch limits plaintext exposure but provides no durable recovery or
  storage-failure independence.
- The encrypted PostgreSQL chain improves point-in-time recoverability from
  logical and host-level failures, but it does not by itself survive loss of the
  shared NAS dataset.
- Capacity planning and alerts must treat canonical `PGDATA` and the no-prune
  encrypted chain as consumers of one shared pool.
- Claims about nightly NAS backup, PBS, Backblaze, or any other independent copy
  require separate operator evidence of existence, freshness, and restoration.
