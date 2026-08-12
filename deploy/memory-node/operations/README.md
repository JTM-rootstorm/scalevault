# Installed operations evidence

This directory contains a content-free evidence template for auditing an
installed ScaleVault Memory Node. Copy the template into a protected operator
evidence store; do not complete it in the repository.

The template complements the
[installed-system verification runbook](../../../docs/runbooks/installed-verification.md).
It is not an executable verifier and an unchanged example is not acceptance
evidence. Populate fields only from current read-only inventory, bounded helper
status, and separately reviewed live gates.

Never attach service environment, credentials, private hostnames or network
coordinates, database URLs, generated NPM configuration, raw journals,
Prometheus dumps, provider responses, decrypted recovery objects, or key
material. Use `pending`, not `pass`, when a gate has not run.
