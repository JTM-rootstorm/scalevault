# Installed operations evidence

This directory contains a content-free evidence template for auditing an
installed ScaleVault Memory Node. Copy the template into a protected operator
evidence store; do not complete it in the repository.

The template complements the
[installed-system verification runbook](../../../docs/runbooks/installed-verification.md).
It is not an executable verifier and an unchanged example is not acceptance
evidence. Populate fields only from current read-only inventory, bounded helper
status, and separately reviewed live gates.

`retention_result=no_prune_dependency_watermark_absent` is the expected current
repository contract: retention validates and deletes nothing. Keep retention
activation `blocked` until an authenticated PITR result and exact dependency/
hold authority exist. Likewise, local archive continuation is not remote
promotion: `verified_remote_promotion_required` leaves the new target disabled
until separately reviewed SSH promotion and a normal exporter append succeed.

Installed observability evidence must cover migration
`0011_observability_aggregates`, both login/capability role pairs and their
fixed security-definer functions, the exact loopback database metrics exporter,
and protected systemd report publication. Repository presence is not installed
acceptance.

Never attach service environment, credentials, private hostnames or network
coordinates, database URLs, generated NPM configuration, raw journals,
Prometheus dumps, provider responses, decrypted recovery objects, or key
material. Use `pending`, not `pass`, when a gate has not run.
