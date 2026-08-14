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

`kivra-memory-operational-metrics-publish` is the narrow root one-shot behind
the local backup/WAL/storage metrics. It reads metadata only from fixed local
paths, uses no network or provider integration, and atomically replaces one
fixed-schema root:`memory-metrics` status file below `/run`. Its systemd timer,
not an ambient command-line path, supplies the production invocation.

`kivra-memory-npm-config-check` validates a protected complete `nginx -T`
capture for the static ScaleVault NPM invariants. It does not replace the live
external-source, spoof, backend-counter, listener, or canary gates in the
[NPM drift runbook](../../../docs/runbooks/npm-drift.md).

`kivra-memory-release-prepare` creates a deterministic `git archive` from one
exact `HEAD` with no tracked or staged drift, records its SHA-256, installs the locked production virtual
environment into a full-revision release directory, and makes that candidate
read-only. Run `prepare` as an unprivileged deployment operator with absolute,
pre-approved paths and the full 40-character commit ID. The release directory
must be its final path because virtual-environment entry points embed it.
Known untracked operator plans are preserved and excluded from the archive.

After repository verification, prepare the final candidate with an absolute
path to `uv`:

```sh
deploy/memory-node/scripts/kivra-memory-release-prepare prepare \
  --repository /absolute/path/to/clean/scalevault \
  --revision FULL_40_CHARACTER_COMMIT \
  --releases-root /opt/kivra-memory/releases \
  --archives-root /opt/kivra-memory/source-archives \
  --uv /absolute/path/to/uv
```

The operator must then review the fixed output, independently verify the
archive checksum, and change the candidate and archive to `root:root` without
changing bytes. `plan-pointer` records the expected current pointer and exact
candidate manifest in a mode-`0600` JSON plan. Review that plan and make it
`root:root` before the authorized root-only `apply-pointer`; apply fails if the
pointer or manifest changed and replaces `/opt/kivra-memory/app` atomically.
The pointer always names a full-revision directory, so the fixed paths in the
systemd units continue to resolve through `/opt/kivra-memory/app`.

`kivra-memory-installed-audit` is read-only and emits one content-free JSON
record. It verifies the atomic pointer, root-owned read-only release and source
archive, revision, source checksum, expected and installed migration, every
console-entry digest, exact installed unit digests, systemd verification, and
bounded unit states. Its digest inventory always requires the exact checked-in
`client-auth` drop-in. By default it requires the optional `sealed-content`
drop-ins to be absent; pass `--sealed-content-enabled` only after their provider,
ledger, accepted anchor, digest-binding credential, accounts, directories, and
restore-reconciliation gate are genuinely provisioned. In that mode the audit
requires the exact checked-in sealed drop-ins. It rejects extra `.conf` files in
either target directory. The sole local adaptation is the exact installed
filename `kivra-memory-codex-ingress.service.d/10-network-policy.conf`; supply its
independently reviewed SHA-256 and the audit binds the verified digest into its
output. A missing or changed policy, invalid digest, or any other extra
`.conf` file fails closed. Credential files are never opened; only credential
name, presence, UID, GID, mode, link count, and byte count are reported.
Command stderr is suppressed so PostgreSQL or systemd diagnostics cannot enter
the evidence stream. Run it only after all checked-in units are installed:

```sh
/usr/local/libexec/kivra-memory-installed-audit \
  --codex-network-policy-sha256 REVIEWED_SHA256 \
  > /protected/content-free-evidence/installed-audit.json
```

This file/digest gate does not replace the separate live review of effective
drop-in composition, service hardening, mounts, listeners, or network shape.

None of these helpers is an unattended live installer. Do not embed
credentials, database URLs, payloads, or private network coordinates in script
arguments, repository configuration, status artifacts, or evidence.

Install every checked-in deployment helper from the accepted release so the
installed audit can compare it to the release manifest:

```sh
install -o root -g root -m 0755 \
  /opt/kivra-memory/app/deploy/memory-node/scripts/kivra-memory-* \
  /usr/local/libexec/
```
