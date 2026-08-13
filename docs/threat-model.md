# Threat model

ScaleVault is a private, single-owner continuity service. PostgreSQL is the
semantic authority; the signed private Forgejo archive and encrypted PostgreSQL
backup chain are independent recovery paths. This model covers only the active
Milestone 10 topology. Public relay, OAuth, node-agent routing, public export,
and third-party enrollment are dormant and must remain unprovisioned.

The protected assets are memory statements and evidence, sealed-content keys,
authorization values and credential material, tenant and subject identifiers,
canonical event order, archive history and signing identity, recovery
availability, and the truthfulness of hard-forget claims. A network location,
VPN membership, proxy header, Git identity, or restored credential row is not
an identity proof by itself.

## Assumptions and security claims

- The host administrator and operator-controlled recovery environment are
  trusted to inspect private content. Other clients, ingress payloads, restored
  state, logs, metrics, and candidate public artifacts are untrusted.
- A compromised canonical host can disclose plaintext available to that host.
  Service sandboxing, forced RLS, and encryption reduce reach and persistence;
  they do not make a fully compromised host trustworthy.
- Backup encryption protects copies only while the private decryption key is
  separate and uncompromised. Archive signatures prove accepted provenance,
  not confidentiality.
- Cryptographic erasure applies only to envelope-encrypted content and only
  when destruction tombstones dominate every allowed key-provider restore.
  It does not prove physical-media sanitization or deletion from unknown copies.
- Repository tests prove deterministic controls. Installed NPM, nftables,
  systemd, PostgreSQL durability, Forgejo, provider revocation, and offsite
  independence require separate live evidence.

## Active-boundary matrix

| Boundary and abuse case | Preventive and detective controls | Verification | Revocation and recovery | Residual risk |
| --- | --- | --- | --- | --- |
| Canonical API/worker to PostgreSQL: a stolen runtime DSN selects another tenant, bypasses application policy, or corrupts event order | Local-only database reachability; distinct non-owner runtime roles; forced RLS; transaction-local tenant context; no `BYPASSRLS` or schema creation; serializable command handlers and append-only events; credentials loaded from protected files | `tests/integration/database/test_roles.py`, `test_security.py`, `test_mutation_concurrency.py`, and `test_event_replay.py`; installed role and socket review | Stop affected services, revoke/replace the database role credential, inspect canonical events, then restore into an isolated database from a verified PITR chain if integrity is lost | A stolen shared service credential can choose any tenant context permitted to that role. RLS is not authentication. A database administrator remains privileged |
| Private NPM/Codex ingress to the loopback Memory Node: public reachability, spoofed forwarding headers, wrong Host/Origin, redirect, path confusion, or oversized/SSE exhaustion | VPN/private-LAN reachability plus a distinct request-scoped bearer; exact HTTPS `/mcp`; explicit source ACL; fixed Host/Origin and method policy; non-TCP real-IP trust reset plus exact proxy-peer pinning; bounded body and concurrency policy; no metrics or admin route | Deployment static tests, fresh NPM generated-config checks, nftables counters, spoof probes, backend counters, and external blackbox probes | Revoke the device bearer independently of VPN membership; remove the VPN peer; disable the Proxy Host and listener while investigating; reissue credentials before reopening | NPM terminates TLS, so the accepted backend hop is plaintext on the same host. Host compromise or a newly exposed proxy path defeats network separation |
| Secure MCP Tunnel and OpenAI control plane: provider-key theft, injected-bearer theft, provider processing, path widening, or unintended mutation reachability | Outbound tunnel targets exact loopback `/chatgpt/mcp`; a separate read-scoped ScaleVault bearer; provider key and bearer stored separately; no direct `/mcp`, admin, or metrics route; payload-safe tunnel profile | `tests/contract/test_chatgpt_read_mcp.py`, `tests/integration/database/test_m8_secure_tunnel_acceptance.py`, tunnel deployment tests, exact live route probes, and provider dashboard review | Revoke both the provider control-plane key and tunnel bearer, stop the tunnel service, measure propagation, and reissue rather than restoring credentials | OpenAI is a live payload-processing boundary. Provider revocation timing and retained provider-side data cannot be inferred from local tests |
| GitHub proposal ingress to poller: malicious proposal body, schema confusion, replay, rollback, force-push, installation substitution, rate limiting, or prompt injection | Disabled by default; create-only private repository; pinned owner/repository/installation identity; strict bounded JSON schemas; immutable snapshot/head tracking; proposals are untrusted nominations and use canonical command handlers | `tests/ingress/`, `tests/unit/ingress/`, `tests/integration/database/test_github_ingress.py`, and provider-side repository/install probes | Disable poller, revoke GitHub installation/provider and local poller credentials separately, preserve heads for investigation, then resume with explicit reconciliation | GitHub is an external availability and metadata boundary. A validly authenticated malicious proposal can still contain adversarial text; canonical selection policy must reject it safely |
| Exporter to private Forgejo archive: deploy-key theft, archive rewrite, signer compromise, unsigned commits, manifest substitution, or concurrent writers | One logical exporter; deterministic manifests and batches; first-parent signed history; pinned remote/known-hosts and allowed signers; bounded decoding; archive is recovery-only, never semantic authority | `tests/archive/`, `tests/integration/database/test_archive_export.py`, `test_archive_restore_acceptance.py`, plus real clone/signature/tamper drills | Stop exporter; revoke deploy key independently of signer trust; preserve divergent histories; rotate signer only under an accepted transition policy; restore to an isolated database | A deploy key and signing key have different blast radii. Removing a compromised old signer may invalidate historical recovery, while retaining it preserves trust in compromised signatures |
| PostgreSQL base backup/WAL producer to encrypted backup store: plaintext staging, WAL gaps, stale verification, retention pruning the last chain, rollback, or co-located key theft | Physical PostgreSQL 17 backups; encryption before durable placement; separate decryption key; verified manifests and WAL continuity; immutable completion markers; retention preserves at least one complete verified chain | Disposable PostgreSQL PITR tests, `pg_verifybackup`, forced missing/corrupt-WAL faults, age alerts, and an isolated live drill | Stop pruning on uncertainty; revoke backup transport credentials; quarantine incomplete chains; create a fresh full backup after credential compromise; never overlay production during restore | Encryption does not protect plaintext in a running database or a host holding the decryption key. Recovery point is bounded by last durable WAL and verified chain |
| Primary archive to secondary encrypted Git bundle/offsite copy: incomplete history, stale copy, tampering, loss of failure-domain independence, or accidental second writer | Full-history bundle derived only after primary verification; encryption with a separate key; digest/signature verification at destination; secondary is read-only and never authors, amends, merges, or force-pushes | Local Git tamper tests, bundle verification, and local restore from the exact offsite-suitable ciphertext; Backblaze placement and retrieval evidence is operator-managed under ADR 0033 | Revoke copy transport credentials, quarantine mismatch, rebuild only from a still-verified primary, or restore primary from a verified secondary without rewriting divergent evidence | Provider/account/legal failures can affect purportedly separate copies. Administrative independence must not be claimed without live evidence, but Backblaze evidence is not an M10 blocker |
| Sealed-content key provider and destruction ledger: key-file theft, forged deletion, restored pre-forget DEK, derivative plaintext, or tombstone rollback | External per-memory DEKs; authenticated envelopes bound to context; destruction-only purge capability; durable tombstones checked before key restore/use; key backups are separate from content backups | `tests/unit/security/`, real PostgreSQL/local-provider purge integration, and recovery-copy non-resurrection drills | Destroy the DEK, persist and replicate its tombstone, remove verified derivatives, and reject every restored key backup whose state is dominated by destruction | Plaintext and frozen Genesis compatibility records are outside this erasure claim. Unlink is not media sanitization; unknown external key copies remain unknowable |
| Services to journals, Prometheus, alerts, and root-local reports: payloads or identifiers escape through errors, labels, commands, tracebacks, or status artifacts | Fixed event names, reason codes, and bounded labels; no statements, evidence, proposal bodies, auth values, DSNs, key bytes, tenant/subject/request IDs, or arbitrary exception strings; protected root-local detailed reports with retention | Unit canaries across success/failure paths; dated scans of metrics, journals, alerts, NPM summaries, and reports; alert fire-and-recover tests | Stop affected exporter/scraper, restrict and expire leaked artifacts, rotate any exposed credential, correct sanitization, then repeat canary scans before restart | Counts and timing can reveal operational activity. Root can access protected local reports. Third-party alert delivery adds a provider boundary if configured |
| Operator recovery environment to restored database/archive: restore overlays production, stale credentials authorize exposure, incompatible revision runs, or exporter rewrites history | Isolated targets only; all API/ingress/tunnel/workers/pollers/exporter disabled; verify backup/archive before import; pin compatible application/Alembic revision; rotate credentials after rollback; explicit exporter re-anchor or new target | Three independent drills: PITR, primary Forgejo history, and secondary encrypted bundle; content-free recovery records | Abort on divergence or unknown identity; preserve evidence; destroy disposable targets after proof; reissue request/provider credentials before any exposure | Recovery operators can see private data. A technically valid old backup may reintroduce vulnerabilities or revoked state unless the post-restore checklist is followed |
| Offline candidate map to leakage scanner/report: raw or encoded private canary, forbidden sealed/evidence/source fields, credential grammar, malformed input, resource exhaustion, link traversal, or diagnostic exfiltration | Pure bounded scan of materialized bytes; raw/NFC/NFKC/Base64/hex/SHA-256 checks; forbidden-field and credential grammar checks; regular-file/type/size/count/path bounds; no link following; fixed-code/count/digest-only result; no MCP or publication surface | `tests/unit/security/test_leakage_scanner.py` positive controls for every contamination class, clean control, resource faults, links, sanitization, and CLI protected input | Treat any finding or internal error as failure; discard the candidate, protect canary inputs, correct transformation outside this component, and rescan exact bytes | Pattern scanning cannot prove semantic anonymity or safe public selection. A passing synthetic scan is not Milestone 11 public-export acceptance |

## Abuse chains and control dependencies

Controls are intentionally layered. VPN reachability without bearer
authentication is insufficient. A valid proposal signature or provider
installation without canonical selection is insufficient. An encrypted backup
without verified WAL continuity is insufficient. A signed archive without
first-parent and manifest-chain validation is insufficient. A destroyed live
DEK without tombstone dominance over restored key backups is insufficient.

The highest-impact cross-boundary chains are:

1. A stolen ingress bearer plus accidental public NPM exposure enables direct
   requests. Both bearer revocation and public-exposure probes are required.
2. A compromised exporter deploy key plus signing key can produce apparently
   authentic private history. Independent canonical database comparison and a
   reviewed signer transition remain required.
3. A retained pre-forget key backup plus retained encrypted content can undo
   erasure. Restore must consult a destruction record from an independent,
   dominating retention path before releasing any key.
4. A payload-bearing exception plus permissive telemetry can turn a rejected
   attack into durable disclosure. Every failure boundary must reduce errors to
   fixed codes before logging or metrics.
5. A valid old restore plus automatically enabled services can revive revoked
   credentials and vulnerable configuration. Recovery stays offline until
   identity, revision, credential, and exposure reviews complete.

## Fault response matrix

| Domain | Injected or observed fault | Required safe outcome |
| --- | --- | --- |
| PostgreSQL | unavailable, serialization conflict, corrupt backup, missing WAL | bounded retry where safe; no partial command; no false successful recovery |
| Forgejo/Git | unavailable, non-fast-forward, bad signature, malformed manifest | preserve divergence, stop exporter/restore, never rewrite to pass |
| Backup encryption | missing recipient/decryption key, truncated ciphertext, stale completion marker | no plaintext artifact accepted; chain remains ineligible |
| Secondary copy | stale, corrupt, same-domain destination, transport revocation | alert and quarantine; primary history is not changed |
| Key provider | missing key, forged tombstone, restored destroyed key | content remains unavailable; destruction dominates restore |
| GitHub/provider | 401/403/404, throttling, rollback, installation mismatch | bounded backoff or disable; no alternate identity or untrusted apply |
| Observability | query failure, malformed state, payload-bearing exception | fixed failure code only; alert without raw exception or identifiers |
| Leakage scanner | malformed JSON/UTF-8, unknown type, duplicate/unsafe path, links, oversize, internal error | nonzero failure with fixed counts and artifact digest only |
| NPM/private ingress | config drift, spoofed header, saturation, public route | zero unapproved backend reachability and explicit operator alert |

## Deferred and non-claims

The scanner does not define a public schema, select records, redact content,
sign an export, create a branch, or publish anything. Those are Milestone 11
architecture and acceptance concerns. No dormant relay, node-agent, OAuth, or
generic enrollment component may be treated as an active recovery or access
path. This model also makes no claim that repository tests establish physical
media erasure, public network absence, provider revocation latency, or offsite
independence without the named live gates.
