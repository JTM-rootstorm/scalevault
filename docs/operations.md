# Operations

Operator endpoints are `/healthz`, `/readyz`, `/metrics`, and a future
authenticated `/admin/status`. They stay on loopback or the management network
and are never exposed as MCP tools.

Production runbooks will cover installation, upgrades, credential rotation,
queue diagnosis, archive verification, relay enrollment, and safe shutdown.
