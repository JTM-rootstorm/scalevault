# Memory Node deployment scripts

Installation and verification remain explicit operator procedures because
existing-node database migration and storage validation require reviewed
decisions. Follow `../systemd/README.md` and `../postgresql/README.md` for the
base node.

`kivra-memory-postgres-backup` implements the fixed-path encrypted physical
backup, WAL archival, verification, retention, and isolated PITR preparation
contract. Install and operate it only through [`../backup/README.md`](../backup/README.md).
It validates mount boundaries and paths, fails closed on unexpected storage,
and emits content-free fixed-field status.

`kivra-memory-npm-config-check` validates a protected complete `nginx -T`
capture for the static ScaleVault NPM invariants. It does not replace the live
external-source, spoof, backend-counter, listener, or canary gates in the
[NPM drift runbook](../../../docs/runbooks/npm-drift.md).

Neither helper is an unattended installer. Do not embed credentials, database
URLs, payloads, or private network coordinates in script arguments, repository
configuration, status artifacts, or evidence.
