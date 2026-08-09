# Forgejo archive target

Forgejo is the durable private archive remote, not a live database. Only the
single logical exporter may push. Production deployment should place the remote
outside the canonical Memory Node failure domain.

Create one dedicated Forgejo service account and one empty private repository.
Attach a repository-scoped SSH deploy key with write access; do not use an
administrator, personal, or shared key. Protect the archive branch against
deletion and force-push. Disable actions, webhooks, mirrors, LFS, releases,
issues, and wiki unless a later reviewed design requires them.

Record the canonical SSH URL, branch, deploy-key fingerprint, and Forgejo SSH
host-key fingerprint in the operator inventory. Pin the host key in
`/etc/kivra-memory/archive-known-hosts`; do not use `accept-new`. Initialize the
Memory Node worktree without storing a remote credential:

```sh
sudo -u memory-exporter git -C /mnt/memory/kivra-memory/archive init \
  --initial-branch=main
```

The branch must match both the `archive_targets` row and exporter environment.
Leave the worktree empty and clean before first startup. The exporter is the
only writer and supplies its SSH URL explicitly with isolated Git configuration.

Alert on any non-exporter commit, rejected push, changed remote parent, or
signature failure. Do not repair divergence with force-push; stop the exporter,
preserve both histories, and investigate. Forgejo availability is not proof of
recoverability: regularly exercise signature, manifest-chain, event-continuity,
and clean-database restore checks in a disposable database while retaining
PostgreSQL base backup and WAL as the preferred recovery path.
