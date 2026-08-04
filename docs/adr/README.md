# Architecture decision records

This directory records durable architecture decisions for ScaleVault. Dated
product capability observations belong in separate operational or capability
documentation and do not change these decisions implicitly.

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-canonical-private-memory-node.md) | Accepted | Keep one canonical private Memory Node and terminate public traffic at the generic relay. |
| [0002](0002-postgresql-events-and-projections.md) | Accepted | Use PostgreSQL as the semantic source of truth with an event log and rebuildable projections; do not add Redis in v1. |
| [0003](0003-forgejo-single-writer-archive.md) | Accepted | Allow only the Forgejo archive exporter to write the archive. |
| [0004](0004-github-append-only-ingress.md) | Accepted | Treat GitHub.com ingress as an append-only transport, not an authority or archive. |
| [0005](0005-memory-content-boundaries.md) | Accepted | Exclude raw transcripts by default and never store hidden reasoning. |
| [0006](0006-external-reverse-proxy.md) | Accepted | Keep reverse-proxy ownership outside the canonical LXC and preserve loopback-only service defaults. |

An accepted ADR may be changed only by a later ADR that explicitly supersedes
it. Implementation changes must preserve the security and authority boundaries
recorded here.
