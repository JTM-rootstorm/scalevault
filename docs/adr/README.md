# Architecture decision records

This directory records durable architecture decisions for ScaleVault. Dated
product capability observations belong in separate operational or capability
documentation and do not change these decisions implicitly.

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-canonical-private-memory-node.md) | Accepted | Keep one canonical private Memory Node as the sole semantic authority; ADR 0022 removes the former public-relay path. |
| [0002](0002-postgresql-events-and-projections.md) | Accepted | Use PostgreSQL as the semantic source of truth with an event log and rebuildable projections; do not add Redis in v1. |
| [0003](0003-forgejo-single-writer-archive.md) | Accepted | Allow only the Forgejo archive exporter to write the archive. |
| [0004](0004-github-append-only-ingress.md) | Accepted | Treat GitHub.com ingress as an append-only transport, not an authority or archive. |
| [0005](0005-memory-content-boundaries.md) | Accepted | Exclude raw transcripts by default and never store hidden reasoning. |
| [0006](0006-external-reverse-proxy.md) | Accepted | Keep reverse-proxy ownership outside the canonical LXC and preserve loopback-only service defaults. |
| [0007](0007-controlled-storage-and-encrypted-backups.md) | Accepted | Use operator-controlled persistent storage and encrypted offsite recovery copies. |
| [0008](0008-versioned-memory-domain-contract.md) | Accepted | Freeze tenant isolation, ontology, provenance, and relational invariants for the v1 memory domain. |
| [0009](0009-canonical-events-and-replay.md) | Accepted | Use UUIDv7 identifiers, transactional event ordering, RFC 8785 hashing, and deterministic replay. |
| [0010](0010-mcp-mutation-command-contract.md) | Accepted | Freeze mutation tools, typed command semantics, fine-grained scopes, concurrency behavior, and the durable storage boundary. |
| [0011](0011-mcp-read-retrieval-and-status-contract.md) | Accepted | Freeze exact-branch read and status tools, privacy-safe results, hybrid ranking, and bounded context output. |
| [0012](0012-versioned-local-embedding-model.md) | Accepted | Use a pinned local 384-dimensional MiniLM model with versioned derived storage and explicit activation. |
| [0013](0013-versioned-selection-policy-and-lifecycle.md) | Accepted | Use a hashed declarative selection profile, immutable decisions, replayable candidate lifecycle, and operator-local private seeds. |
| [0014](0014-genesis-first-import-contract.md) | Accepted | Import the exact Genesis snapshot through immutable provenance, a narrow compatibility correction, and SelectionEngine-only policy gates. |
| [0015](0015-deterministic-signed-archive-and-restore.md) | Accepted | Export and restore a deterministic, signed, single-writer recovery archive with external trust anchors. |
| [0016](0016-github-ingress-v2-runtime.md) | Accepted | Poll immutable GitHub proposal-v2 objects through the policy engine with quarantine and a non-sensitive transport boundary. |
| [0017](0017-sealed-canonical-memory-content.md) | Accepted | Store protected content only in versioned authenticated envelopes backed by external per-memory keys. |
| [0018](0018-request-scoped-bearer-authentication.md) | Accepted | Authenticate direct-private clients with request-scoped bearer credentials and database-derived identity. |
| [0019](0019-chatgpt-secure-tunnel-read-access.md) | Accepted | Expose a query-only ChatGPT MCP surface through a pinned, single-workspace secure-tunnel bearer identity. |
| [0020](0020-relay-enrollment-and-transport.md) | Superseded | Bind one-use node enrollment, mTLS connection identity, and bounded relay transport without granting memory authority. |
| [0021](0021-relay-oauth-and-forwarded-identity.md) | Superseded | Bind public OAuth subjects to installations and canonical relay identities through body-bound, replay-safe signed assertions. |
| [0022](0022-private-single-owner-access-topology.md) | Accepted | Use Secure MCP Tunnel for ChatGPT Web and per-device direct-private identities over the owner's VPN; do not deploy a public relay. |
| [0023](0023-bounded-loopback-mcp-http-boundary.md) | Accepted | Pin loopback MCP transport security, request bounds, and forwarding-header rejection without weakening the tunnel boundary. |
| [0024](0024-dedicated-private-codex-ingress.md) | Accepted | Run a separate direct-only private listener behind the LAN/VPN HTTPS proxy while keeping ChatGPT and operator routes on loopback. |
| [0025](0025-proxy-terminated-tls-for-private-ingress.md) | Accepted | Terminate Let's Encrypt TLS at Nginx Proxy Manager and use an exact-source private HTTP hop to the Codex ingress. |
| [0026](0026-npm-static-acme-renewal-exception.md) | Accepted | Permit NPM's static, non-proxied ACME challenge prefix while keeping every ScaleVault application route private. |
| [0027](0027-encrypted-postgresql-pitr-and-recovery-sets.md) | Accepted | Use continuous encrypted PostgreSQL PITR with daily verified base backups, independently held recovery identities, and protected recovery chains. |
| [0028](0028-monotonic-sealed-key-destruction.md) | Accepted | Make a separately rooted and externally anchored monotonic destruction ledger dominate every restored sealed-key backup. |
| [0029](0029-archive-recovery-continuation-and-signer-epochs.md) | Accepted | Recover through anchored signed history, bounded signer epochs, new-target continuation by default, and an encrypted full-history secondary bundle. |
| [0030](0030-credential-lifecycle-and-revocation.md) | Accepted | Give every credential an explicit rotation, revocation, compromise, and recovery contract, including no post-revocation GitHub ingress processing. |
| [0031](0031-private-observability-and-operator-audit.md) | Accepted | Keep telemetry private and bounded, payload-blind aggregate collection least-privileged, and identity-specific reports root-local. |
| [0032](0032-offline-public-artifact-leakage-scanner.md) | Accepted | Fail closed with a pure bounded offline scanner before any future public artifact can be signed or published. |
| [0033](0033-operator-managed-offsite-and-local-alert-acceptance.md) | Accepted | Keep Backblaze transfer operator-managed and make private local alert evaluation, rather than external notification delivery, the M10 acceptance boundary. |

An accepted ADR may be changed only by a later ADR that explicitly supersedes
it. Implementation changes must preserve the security and authority boundaries
recorded here.
