# ADR 0007: Controlled storage and encrypted backups

- Status: Accepted
- Date: 2026-08-03
- Supersedes: None
- Refines: ADR 0001 and ADR 0003

## Context

The Memory Node LXC uses `/mnt/memory`, an NFSv4 dataset hosted by hardware and
services administered by the ScaleVault operator. The dataset is the required
location for PostgreSQL and other persistent non-package data. Its ACL permits
the trusted deployment environment to modify the dataset. Disaster-recovery
copies are sent offsite in encrypted form.

This is an operator-chosen trust boundary. Treating every principal within that
controlled environment as mutually hostile would not match the deployment
model and would obstruct the requested storage and backup design.

## Decision

ScaleVault accepts the operator-controlled NAS and NFS service as the persistent
storage boundary for canonical database data, WAL and backups, archive
worktrees, exporter state, and other non-package durable data. These paths live
below `/mnt/memory`; services must not fall back to the LXC root filesystem when
the mount is unavailable.

Runtime credentials, API keys, signing keys, encryption keys, and database
password files remain on the LXC's local root-controlled filesystem or in an
external key facility. The NAS dataset is not used as a credential store.

Offsite copies are encrypted before or as part of the controlled backup
pipeline and are restore-only. They are not a semantic authority, live archive
remote, ingress transport, relay cache, or ordinary retrieval path. Recovery
must validate backup integrity before restoring into operator-controlled
storage.

ADR 0004's explicitly consented GitHub proposal transport remains a transport,
not a backup or canonical storage tier.

## Consequences

- Broad modify permission inside the operator-controlled storage environment is
  accepted and is not a milestone blocker.
- Mount gating, PostgreSQL locking and durability, checksums, bounded retention,
  and restore testing remain operational correctness requirements.
- Encrypted offsite backups do not receive ScaleVault runtime credentials or
  decryption/signing keys as part of the same backup object.
- Hard-forget guarantees must account for retained backups and snapshots; key
  destruction provides the immediate erasure boundary for protected payloads.
- A future move to storage administered by another party requires a new threat
  and encryption review.
