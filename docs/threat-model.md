# Threat model

ScaleVault is a private, single-owner continuity service. PostgreSQL is the
semantic authority; the encrypted PostgreSQL backup chain, verified local
signed history, and encrypted local bundle are distinct recovery paths. Their
storage failure domains are qualified explicitly below. This
model covers only the active Milestone 10 topology. Forgejo provider operation,
archive continuation, public relay, OAuth, node-agent routing, public export,
and third-party enrollment are dormant or excluded and must remain
unprovisioned.

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
- Canonical PostgreSQL `PGDATA` and the encrypted PostgreSQL PITR store occupy
  separate write-scoped directories on the same `/mnt/memory` NFS dataset and
  capacity pool. Directory separation is not protection from mount, NAS,
  dataset, or pool failure.
- Cryptographic erasure applies only to envelope-encrypted content and only
  when destruction tombstones dominate every allowed key-provider restore.
  It does not prove physical-media sanitization or deletion from unknown copies.
- Repository tests prove deterministic controls. Installed NPM, nftables,
  systemd, PostgreSQL durability, and active-provider revocation require
  separate live evidence. PBS protection and Backblaze upload are
  operator-managed; M10 makes no offsite placement, freshness, retention,
  retrieval, or deletion claim.

## Active-boundary matrix

| Boundary and abuse case | Implementation and controls | Tests | Runbook and M10 evidence class | Residual risk |
| --- | --- | --- | --- | --- |
| Canonical API/worker to PostgreSQL: a stolen runtime DSN selects another tenant, bypasses policy, or corrupts event order | `storage/event_store.py`, `domain/commands.py`, forced-RLS migrations, and `deploy/memory-node/postgresql/`: local-only distinct non-owner roles, transaction-local tenant context, serializable commands, append-only events, protected credential files | `tests/integration/database/test_roles.py`, `test_security.py`, `test_mutation_concurrency.py`, `test_event_replay.py` | [Installed verification](runbooks/installed-verification.md), [credentials](runbooks/credentials.md), and [PITR](runbooks/postgresql-pitr.md); fixed grant/denial, hash-chain, recovery, credential-reissue, and cleanup results | A stolen shared service credential can choose any tenant context permitted to that role. RLS is not authentication; a database administrator remains privileged |
| Private NPM/Codex ingress: public reachability, spoofed forwarding identity, route confusion, or resource exhaustion | `api/codex_ingress.py` and `deploy/memory-node/private-ingress/`: request bearer, exact HTTPS `/mcp`, source ACL, Host/Origin/method policy, real-IP trust reset, proxy-peer pinning, and bounded resources | `tests/unit/api/test_codex_ingress.py`, `tests/unit/deploy/test_codex_ingress_deployment.py` | [NPM drift](runbooks/npm-drift.md) and [credentials](runbooks/credentials.md); fixed config counts, probe results, zero rejected-request backend increments, revocation result, and clean canary counts | NPM terminates TLS; host compromise or another exposed proxy path defeats separation |
| Secure MCP Tunnel and OpenAI control plane: provider-key or injected-bearer theft, path widening, or unintended mutation reachability | `runtime/` transport/authentication and `deploy/memory-node/tunnel/`: exact loopback `/chatgpt/mcp`, separate read-scoped bearer, separated credentials, no direct mutation/admin/metrics route | `tests/contract/test_chatgpt_read_mcp.py`, `tests/integration/database/test_m8_secure_tunnel_acceptance.py`, `tests/unit/deploy/test_tunnel_deployment.py` | [Credentials](runbooks/credentials.md) and [installed verification](runbooks/installed-verification.md); fixed intended-route, mutation-denial, provider-revocation, old-session, and canary results | OpenAI is a live payload-processing boundary; provider revocation timing and retained provider-side data require direct observation |
| Optional GitHub proposal ingress: malicious body, schema confusion, replay, rollback, installation substitution, or prompt injection | `ingress/`, `application/github_ingress.py`, and strict proposal schemas: disabled by default, pinned repository/installation identity, immutable head tracking, bounded untrusted nominations, canonical command handlers | `tests/ingress/`, `tests/unit/ingress/`, `tests/integration/database/test_github_ingress.py` | [Credentials](runbooks/credentials.md), [shutdown/startup](runbooks/shutdown-startup.md), and [installed verification](runbooks/installed-verification.md); disabled-and-unprovisioned `not-applicable`, otherwise fixed provider/local revocation and no-progress results | GitHub is an external availability and metadata boundary; authenticated proposals can still contain adversarial text |
| Local signed archive and encrypted bundle: signer compromise, unsigned or substituted history, incomplete objects, wrong identity, or ciphertext corruption | `archive/trust.py`, `verification.py`, `bundle.py`, `restore.py`, and `tools/archive_recovery.py`: external anchors, bounded complete signed history, authenticated encryption, clean local database restore; no provider or continuation dependency | `tests/archive/`, `tests/integration/archive/test_git_recovery.py`, `test_encrypted_bundle_cli.py`, `tests/integration/database/test_archive_restore_acceptance.py` | [Secondary-bundle recovery](runbooks/secondary-bundle-recovery.md) and [drill cleanup](runbooks/drill-cleanup.md); exact head/manifest/high-water/signer-policy/object-byte equality, negative-result codes, restored-integrity counts/digests, and cleanup | Retained public trust can preserve historical acceptance of a later-compromised signer. M10 makes no Forgejo, remote equality, cadence, continuation, exporter, or offsite claim |
| PostgreSQL base/WAL producer to encrypted local store: plaintext staging, WAL gap, stale verification, deletion, rollback, co-located private identity, or shared-pool exhaustion | `deploy/memory-node/scripts/kivra-memory-postgres-backup` and backup units: PostgreSQL 17 physical backup, local plaintext scratch, encryption before durable placement, separately supplied identity, verified manifests/continuity, atomic markers, zero-deletion retention validation | `tests/integration/backup/test_postgres_pitr.py`, `tests/unit/deploy/test_backup_deployment.py`, `pg_verifybackup`, missing/corrupt-WAL negatives | [Backup operations](runbooks/backup-operations.md), [WAL failure](runbooks/wal-failure.md), and [PITR](runbooks/postgresql-pitr.md); bounded object/timeline IDs, counts/digests, continuity, `no_prune_dependency_watermark_absent`, combined-pool capacity, unchanged inventory, RPO/RTO, and cleanup | A running database and local staging expose plaintext. Canonical `PGDATA` and the encrypted chain share `/mnt/memory`, its NAS/dataset failure domain, and capacity; recovery is bounded by the last durable WAL. No M10 process may delete recovery objects. Nightly NAS backup, PBS, and Backblaze remain operator-managed and unclaimed |
| Sealed-content key provider and destruction ledger: key theft, forged deletion, restored pre-forget DEK, derivative plaintext, or tombstone rollback | `security/sealed_content.py`, `destruction_ledger.py`, `destruction_broker.py`, and sealed systemd units: external DEKs, context-bound envelopes, narrow destruction broker, independently anchored ledger, restore reconciliation | `tests/unit/security/test_local_key_provider.py`, `test_destruction_ledger.py`, `test_destruction_broker.py`, `test_sealed_content.py`, plus installed stale-provider/PITR non-resurrection drill | [Installed verification](runbooks/installed-verification.md), [PITR](runbooks/postgresql-pitr.md), and [drill cleanup](runbooks/drill-cleanup.md); correlation/inventory digests, anchor count/head, fixed purge/tombstone/reconcile/read-denial results, and cleanup | Plaintext and frozen Genesis records are outside the claim; unlink is not media sanitization and unknown external key copies remain unknowable |
| Services to journals, Prometheus, alerts, and root-local reports: payloads, identifiers, credentials, or raw exceptions escape | `observability/`, migration `0011_observability_aggregates.py`, metrics/report units, local rules, and `security/operational_canary.py`: fixed fields/labels, least-privilege aggregate functions, bounded loopback exporter, distinct loopback PostgreSQL-up exporter, protected reports and exact-capture canary scans | `tests/unit/observability/`, `tests/unit/security/test_operational_canary.py`, `tests/unit/deploy/test_monitoring_rules.py`, `test_metrics_exporter_deployment.py`, `test_operator_report_deployment.py` | [Installed verification](runbooks/installed-verification.md) and [incident response](runbooks/incident-alerts.md); fixed collector/scrape/rule/fault states for checked-in producers, zero evaluation errors, bounded report metadata, age/byte-cap results, and scanner `clean` with zero matches | Counts/timing reveal activity and root can read protected reports. External alert delivery is a non-blocking, unevaluated provider boundary |
| Operator recovery environment: restore overlays production, stale credentials authorize exposure, incompatible revision runs, or writers start early | backup helper, `archive/restore.py`, restore-reconcile unit, immutable releases, and systemd write/listener isolation: disposable plaintext targets below `/var/lib/kivra-memory/recovery` on the isolated recovery host, independently supplied trust/credentials, compatibility and destruction checks before reads | installed PostgreSQL 17 PITR plus local signed-history and same-anchor encrypted-bundle restores; targeted deployment tests | [PITR](runbooks/postgresql-pitr.md), [secondary bundle](runbooks/secondary-bundle-recovery.md), [shutdown/startup](runbooks/shutdown-startup.md), and [cleanup](runbooks/drill-cleanup.md); compatibility/integrity, write-disable, credential/destruction reconciliation, RPO/RTO, cleanup, and independent second-check results | Recovery operators can see private data; local recovery scratch is not a durable or independent copy; a valid old backup may revive vulnerable or revoked state unless activation remains gated |
| Offline candidate map to leakage scanner/report: raw or encoded canary, forbidden fields, credential grammar, malformed input, exhaustion, links, or diagnostic exfiltration | `security/leakage_scanner.py`: pure bounded byte scan, raw/normalized/encoded/digest checks, forbidden-field and credential grammar checks, strict file/path/resource bounds, fixed output only | `tests/unit/security/test_leakage_scanner.py` clean and contaminated controls, resource faults, links, sanitization, and protected-input CLI tests | [Installed verification](runbooks/installed-verification.md) and [drill cleanup](runbooks/drill-cleanup.md); only `ok`, `artifact_sha256`, fixed counts/result codes, and cleanup confirmation | Pattern scanning cannot prove semantic anonymity. A pass neither authorizes nor accepts M11 public export |

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
2. A compromised signing key can produce apparently authentic local history.
   External anchors, exact compromise cutoffs when declared, and independent
   canonical database comparison remain required. Forgejo deploy-key risk is
   deferred with the provider path.
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
| Local signed Git recovery | bad signature, malformed manifest, anchor mismatch, incomplete objects | preserve divergence, stop restore, never rewrite to pass |
| Backup encryption | missing recipient/decryption key, truncated ciphertext, stale completion marker | no plaintext artifact accepted; chain remains ineligible |
| Local encrypted bundle | stale, corrupt, wrong identity, incomplete objects | fail and quarantine; signed source history is not changed |
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
media erasure, public network absence, provider revocation latency, Forgejo
recovery or continuation, or offsite independence. PBS and Backblaze evidence
remains operator-managed and outside M10. The same is true of nightly NAS
backups: without separate operator evidence, this model makes no claim that any
operator-managed copy exists, is fresh, or has been restored.
