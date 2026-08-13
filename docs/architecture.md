# Architecture

ScaleVault has one canonical private Memory Node. PostgreSQL owns semantic
state. ChatGPT Web reaches the query-only route through outbound Secure MCP
Tunnel, while owner-controlled Codex devices use distinct direct-private
identities after joining the private network through the operator's VPN.
GitHub ingress may carry explicitly approved proposals but is not an alternate
memory store. Local signed-archive verification and encrypted-bundle recovery
provide provider-independent semantic recovery. Forgejo remains a supported
future archive provider, but its operation is excluded from Milestone 10.

Shared contracts are versioned and reviewed centrally. All write transports
must converge on the same policy and concurrency-safe domain command layer.
The private GitHub proposal repository evolves independently; its current and
legacy contract boundary is tracked in
[GitHub ingress compatibility](ingress-compatibility.md) and must be re-audited
before importer work resumes.

The canonical Memory API and PostgreSQL remain restricted to loopback or an
approved local Unix socket. Secure MCP Tunnel reaches the query-only ChatGPT
surface through that local boundary. Owner-controlled Codex devices use a
separate direct-private process behind NPM: exact private HTTPS `/mcp`
terminates at NPM and is proxied over one firewall-bounded private HTTP hop to
the dedicated listener on port 8443. Every request still requires its own
direct-private bearer; VPN membership and NPM reachability do not establish a
ScaleVault identity.

The NPM route is deliberately narrow. It rejects other application paths,
queries, redirects, public sources, and caller-controlled forwarding identity.
The generated host replaces inherited RFC1918 real-IP trust with
`set_real_ip_from unix:;` and `real_ip_recursive off;`; Block Common Exploits is
disabled for this host so NPM cannot bypass the owned fixed-rejection behavior.
The backend is plaintext by the accepted proxy-terminated design and is
therefore protected by the exact listener bind, systemd IP policy, and an
independent host firewall. The canonical API, PostgreSQL, metrics, and operator
surfaces are never exposed through this ingress.

These controls were accepted at Milestone 9; see the
[Milestone 9 acceptance record](milestone-9-private-ingress-progress-2026-08-10.md)
and [ADR 0024](adr/0024-dedicated-private-codex-ingress.md). The canonical node
must never be directly reachable from the public internet.

The public relay and node-agent are superseded, dormant implementation history.
They are not installed, started, or supported by the selected v1 topology.

## Recovery planes

PostgreSQL 17 is the preferred recovery source. Encrypted physical base backups
and continuous WAL form one verified recovery chain; encryption identity is
kept outside the objects it protects. A recovery never overlays the active
cluster.

The signed local archive is an independent semantic recovery source, not a
second canonical database. A verified encrypted full-history bundle supplies a
second provider-independent archive copy. Neither archive path contains runtime
credentials, sealed-content keys, embeddings, worker leases, exporter
checkpoints, or deployment configuration. Milestone 10 verifies exact local
signed history and restores the encrypted bundle into a clean disposable
database; it makes no archive-cadence, remote-equality, or remote-provider
claim.

Archive trust is held outside Git. Recovery pins the exact target, branch,
head, final manifest digest, event high-water mark, compatible release and
Alembic revision, signer epochs, and public-key fingerprints. A planned signer
change has one canonical transition record signed by both old and new keys. A
compromised epoch remains usable only through an independently anchored exact
last-accepted commit and event sequence; later commits from that signer are
rejected. Recovery never learns a new signer from archive content.

Forgejo fetch/restore, remote target promotion, archive checkpoint
reconstruction, continuation, and exporter reactivation are future operational
work rather than Milestone 10 gates. The historical Forgejo runbook is retained
for that separately authorized work. No local test appender or direct
`update-ref` operation is accepted as production continuation evidence, and
existing-target re-anchoring remains unsupported.

This M10 scope is frozen by
[ADR 0034](adr/0034-local-signed-archive-m10-acceptance.md). Recovery retention
is validation-only under
[ADR 0035](adr/0035-no-prune-recovery-retention.md): every base, WAL/history
object, restore point, and hold is retained. The eight-daily/five-weekly values
are accumulation and inventory floors, not deletion authority. Capacity
pressure stops backup production; it does not authorize pruning. PBS protection
and Backblaze upload remain operator-managed outside ScaleVault's M10 gates.

## Observability plane

Database telemetry has no table-reading service credential. The
`kivra_memory_metrics` login can set only the `kivra_memory_observability`
capability, which can execute the fixed-shape
`scalevault_observability_snapshot(uuid)` security-definer function. A
dedicated `memory-metrics` process refreshes that bounded snapshot every 30
seconds and exposes it only on `127.0.0.1:9098`. Collection failure clears the
database-derived samples and reports the collector down.

Protected operator reports use a separate
`kivra_memory_operator_report_login` wrapper and
`kivra_memory_operator_report` capability over the reviewed fixed-shape report
functions. The root-local systemd instance writes one new mode-`0600` report;
it has no remote route and never streams report contents to the journal.

All recovery paths start with writers and external listeners disabled. They
verify source anchors, compatibility, and destruction state before service
activation. Divergence is preserved and investigated; neither Git history nor
canonical state is rewritten merely to make a drill pass. Detailed procedures
are indexed by [Backup and restore](backup-restore.md).
