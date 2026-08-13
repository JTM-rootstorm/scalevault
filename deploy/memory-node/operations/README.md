# Installed operations evidence

This directory contains a content-free evidence template for auditing an
installed ScaleVault Memory Node. Copy the template into a protected operator
evidence store; do not complete it in the repository.

The template complements the
[installed-system verification runbook](../../../docs/runbooks/installed-verification.md).
It is not an executable verifier and an unchanged example is not acceptance
evidence. Populate fields only from current read-only inventory, bounded helper
status, and separately reviewed live gates.

`no_prune_retention.expected_result=no_prune_dependency_watermark_absent` is
the expected M10 contract: validation has zero deletion authority. The expected
code is not evidence by itself. Record the actual result, exact before/after
inventory digests, zero deletion attempts, unchanged restore points and holds,
and adequate capacity. Add one inventory entry for each of base objects,
WAL/history objects, restore points, holds, verification markers,
indexes/manifests, and status artifacts. M10 does not activate destructive
retention.

Forgejo provider recovery, archive continuation, remote promotion, and normal
exporter append are fixed `excluded-not-evaluated` scope declarations. They are
not pending gates and are not successful test results. The local encrypted
bundle remains pending until materialized history also restores into a clean
disposable database with exact source-head, manifest, high-water, signer-policy,
and object-byte binding.

`frozen_release` is the immutable runtime revision installed and tested with the
recorded archive checksum. `evidence_revision` may be a later commit only when
its diff is limited to bounded evidence and acceptance text. If executable
behavior, configuration, schema, migrations, generated artifacts, or
dependencies change, freeze and validate a new release instead of labeling the
descendant evidence-only.

Installed observability evidence must cover migration
`0011_observability_aggregates`, both login/capability role pairs and their
fixed security-definer functions, the exact loopback database metrics exporter,
and protected systemd report publication. Repository presence is not installed
acceptance.

Create one `credential_class_results` entry for every active non-Forgejo class:
direct Codex ingress; Secure MCP Tunnel; OpenAI association/control plane when
provisioned; applicable PostgreSQL application, metrics, report, worker, backup,
and migration identities; backup public-recipient/private-identity custody;
sealed digest binding; Bearer HMAC/client-token pepper; content-key authority;
and optional GitHub ingress when active. Rotatable credentials must record
replacement, intended operation, next-use rejection, session termination,
provider revocation when applicable, rollback posture, canary, and cleanup.
Custody and recovery classes whose old material must remain usable for retained
objects record `not-applicable` for unsafe rotation/revocation fields and prove
custody, availability, intended recovery use, canary absence, and cleanup.

Create one `retention_cap_results` entry for each required class: application
and service journals, PostgreSQL logs, tunnel JSON, NPM/container logs,
Prometheus history, local alert state, and protected operator/recovery/
acceptance reports. Record age and byte-cap results separately. The monitoring,
offline scanner, cross-process canary, NPM spoof/backend-counter, cleanup, and
independent second-check fields remain pending until their live gates run. Add
one monitoring fault entry for each locally applicable alert family rather than
collapsing several injections into one result.

Never attach service environment, credentials, private hostnames or network
coordinates, database URLs, generated NPM configuration, raw journals,
Prometheus dumps, provider responses, decrypted recovery objects, or key
material. Use `pending`, not `pass`, when a gate has not run.
