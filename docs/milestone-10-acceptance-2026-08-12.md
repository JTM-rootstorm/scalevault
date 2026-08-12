# Milestone 10 security, backup, and operations acceptance

- **Review date:** 2026-08-12
- **Status:** Not accepted; implementation and evidence collection in progress
- **Implementation baseline:** `dddf3fe9994752f889345da7b484ac709d43afcb`
- **Accepted source:** Pending final reviewed commit
- **Source archive checksum:** Pending final immutable source archive
- **Database migration revision:** Pending installed-system verification

This is the final record structure required by the M10 plan. It deliberately
does not turn source implementation, unrun commands, or prior Milestone 9
evidence into M10 acceptance. Every row remains pending until the named current
repository, durable PostgreSQL 17, installed-host, provider, and recovery gates
produce reviewed content-free evidence.

## Content-free evidence boundary

This record may contain release and migration revisions; bounded backup/object
identifiers; source-head, manifest, ciphertext, and aggregate digests; target
time or LSN; elapsed time and RPO/RTO; counts; fixed result codes; credential
reissue posture; write-disable and cleanup confirmation; and issue references.

It must not contain memory statements, evidence, proposal bodies, request,
actor, client, credential, installation, or subject identifiers; authorization
values; database URLs; private hostnames or network coordinates; key bytes;
decrypted backup contents; raw exceptions; command lines containing sensitive
values; or unbounded journal, metric, provider, or configuration output. Use
the [content-free evidence template](runbooks/evidence-template.md) in a
protected operator store and transfer only permitted fields here.

## Exit-criteria matrix

| Gate | Required evidence class | Status | Evidence/reference |
|---|---|---|---|
| Architecture and threat decisions accepted | Review | Pending | Required M10 decisions and threat rows not yet accepted in this record |
| Complete repository verification | Repository | Pending | `make PNPM='npx --yes pnpm@10.15.0' verify` not yet recorded |
| Required PostgreSQL 17 integration gate | Durable local | Pending | Zero-skip required database suite not yet recorded |
| Production-relevant PITR durability | Durable local | Pending | Separate WAL/fsync recovery suite not yet recorded |
| Installed services and credentials hardened | Installed LXC | Pending | Exact installed units/credentials/hardening not yet audited |
| Encrypted base backup and WAL current | Installed LXC/storage | Pending | Verified complete chain not yet recorded |
| Isolated PostgreSQL PITR succeeds | Recovery drill | Pending | Real PITR drill not yet run/recorded |
| Primary Forgejo clean restore succeeds | Provider/recovery drill | Pending | Real read-only clone and restore not yet run/recorded |
| Secondary encrypted bundle restore succeeds | Offsite/recovery drill | Pending | Independent failure-domain drill not yet run/recorded |
| Archive continuation policy succeeds | Recovery drill | Pending | Isolated continuation/re-anchor proof not yet recorded |
| Credential revoke/rotation bounds pass | Installed/provider | Pending | Per-class current gates not yet recorded |
| Privacy-safe observability and alerts pass | Repository/installed | Pending | Rule tests, delivery, fault injection, and canary scans pending |
| Leakage scanner detects every synthetic canary | Repository/durable local | Pending | Current complete scanner suite not yet recorded |
| Hard forget dominates all retained recovery copies | Durable local/recovery | Pending | Database/archive/key-backup non-resurrection pending |
| NPM/public-exposure boundary remains closed | Installed/external | Pending | Fresh generated-config and spoof/backend-counter proof pending |
| Drill cleanup completes | Installed/recovery | Pending | Exact cleanup inventory and second check pending |

The milestone remains **not accepted** while any required row is pending,
failed, or skipped.

## Architecture and threat decisions

Status: **Pending review**.

Record the accepted decisions for encrypted PostgreSQL PITR/recovery sets;
monotonic destruction across key backups; archive rollback/signer transition
and continuation; credential lifecycle; telemetry, retention, and evidence;
and fail-closed leakage scanning. Map every implementation test and runbook to
the active-topology threat matrix. Dormant relay, node-agent, OAuth, public
plugin/submission, and generic enrollment paths must remain explicitly
non-applicable and unprovisioned.

## Repository verification

Status: **Pending**.

Record the final source commit and immutable source checksum, targeted suite
result counts, complete `make verify` result, deterministic generated-artifact
checks, alert syntax/tests, systemd/NPM static checks, and approved package
manager substitution if required. No results are claimed here yet.

## Durable PostgreSQL 17 verification

Status: **Pending**.

The clean Debian gate must run with PostgreSQL 17 binaries explicitly selected
and database tests required:

```bash
SCALEVAULT_TEST_PG_BINDIR=/usr/lib/postgresql/17/bin \
SCALEVAULT_REQUIRE_DATABASE_TESTS=1 \
uv run --locked pytest tests/integration
```

Record zero skipped required tests. Run the PITR durability suite separately
with production-relevant WAL, checksums, and fsync behavior; a skipped or
synthetic-only recovery test does not satisfy M10.

## Installed service and credential hardening

Status: **Pending live evidence**.

Follow [Installed-system verification](runbooks/installed-verification.md).
Record accepted unit and executable digests, exact enabled/disabled service
classes, timer status, reviewed systemd hardening, secret-delivery result,
listener class result, core-dump/log-retention result, and per-credential-class
revocation/rotation outcome. Do not include unit/environment contents or
provider responses.

## Encrypted base-backup and WAL evidence

Status: **Pending live evidence**.

Record safe base-backup object identifier, ciphertext/manifest digests,
completed/verified timestamps, WAL continuity result, recovery-window result,
offsite-copy age/result, retention decision, and confirmation that the routine
node did not contain the recovery private identity. Backup creation and
verification do not close the PITR drill below.

## PostgreSQL PITR drill

Status: **Pending; not run or accepted by this record**.

Follow [PostgreSQL PITR](runbooks/postgresql-pitr.md). Record selected target
kind/value, achieved recovery point, timeline/system result codes, exact
migration and extension results, aggregate counts/digests, archive-prefix and
canary results, credential/destruction reconciliation, RPO/RTO, write-disable
proof, and cleanup confirmation.

## Primary Forgejo restore drill

Status: **Pending; not run or accepted by this record**.

Follow [Forgejo recovery](runbooks/forgejo-recovery.md). Record source head and
external-anchor digests, pinned-host-key result, complete signed-chain and
manifest results, compatible revision, clean-destination preflight,
aggregate/canary results, archive-exclusion proof, RTO, and cleanup.

## Secondary encrypted bundle drill

Status: **Pending; not run or accepted by this record**.

Follow [Secondary-bundle recovery](runbooks/secondary-bundle-recovery.md).
Record ciphertext and plaintext-bundle digests, authenticated decryption and
`git bundle verify` result codes, exact ref/head, signed-history and clean
restore results, canaries, RTO, and verified removal of every plaintext scratch
object. Do not record the private recovery identity.

## Archive continuation evidence

Status: **Pending**.

Record the new-immutable-target policy, the fixed
`new_immutable_archive_target_required` recovery result, database/archive
prefix relationship, external rollback anchor, isolated new-target result,
first subsequent exporter checkpoint result, and confirmation that production
history was not rewritten. Existing-target re-anchor is not supported.
Divergence is a failure requiring preservation and investigation.

## Observability, alerts, and retention

Status: **Pending repository and live evidence**.

Record fixed-label/cardinality test results; Prometheus rule syntax and unit
tests; installed scrape and rule health; backup, WAL, offsite, archive, queue,
database, pool, storage, tunnel, credential, ingress, exposure, purge, and
recovery-drill alert fault injections; delivery outcomes; journald/NPM/
PostgreSQL/monitoring retention review; and root-only operator-report bounds.

## Leakage scanner and hard-forget gates

Status: **Pending**.

Record only scanner result codes/counts for every planted synthetic canary
class across candidate public artifacts, metrics, alerts, journals, NPM output,
operator reports, and evidence templates. A passing scanner is not public
export acceptance.

The offline candidate-artifact gate uses
`kivra-memory-scan-public-artifact`. Retain only its `ok`,
`artifact_sha256`, and fixed `counts` fields. Required negative cases cover raw,
normalized, Base64, hex, and digest canaries; forbidden fields and credential
grammar; invalid/duplicate paths; forbidden type or size; malformed encoding;
links/special files; invalid canary input; and sanitized internal failure. Any
nonzero count or nonzero exit is fail closed.

Record the envelope-encrypted synthetic hard-forget test across canonical
PostgreSQL, private archive, secondary copy, PITR, Forgejo-only recovery,
bundle recovery, and every permitted key backup. Acceptance is bounded to
cryptographic erasure inside those tested copies. Record that the independent
current destruction ledger was excluded from key backups, survived each
rollback boundary, and dominated stale restored keys. It must not claim plaintext
or Genesis compatibility records were cryptographically erased, that unlink is
physical sanitization, or that unknown external copies do not exist.

## Provider and live evidence

Status: **Pending**.

Record fresh NPM generated-config and external source/spoof/backend-counter
results; exact private/canonical listener result; direct and Secure Tunnel
credential gates; Forgejo deploy-key/host-key gates; GitHub provider gates only
if the optional ingress is provisioned; alert delivery; real canary scans; and
actual independent Forgejo/offsite recovery.

Non-applicable paths: public relay, node-agent, OAuth, public plugin submission,
generic third-party enrollment, public branch/export/publication, and
branch/descendant semantics remain dormant or deferred. Optional GitHub ingress
may be `not-applicable` only when verified disabled and unprovisioned.

## Cleanup and remaining risks

Status: **Pending**.

Record removal of temporary credentials, decrypted objects, restored database
storage, scratch configuration, recovery identities staged for drills, firewall
counters, and protected generated-config/log copies. Confirm exact production
state was unchanged and a second check found no synthetic canary residue.

Remaining risks must be referenced by reviewed issue or decision identifier,
not described with sensitive details. Cleanup failure prevents acceptance.

## Milestone 11 and deferred boundary

M10 does not add or accept branch creation, copy-on-write ancestry,
public-seed promotion, a public artifact schema, deterministic public
transformation, a public repository/branch/workflow, descendant identity, or
publication. The leakage scanner is only a bounded safety primitive. Real
public-output design and acceptance remain Milestone 11.

Plaintext-to-sealed migration for Genesis compatibility records, claims about
unknown third-party copies or physical-media deletion, multi-tenant archive v1
expansion, backend TLS behind NPM, public operator/metrics routes, and dormant
relay/OAuth/node-agent surfaces also remain outside this acceptance.

## Acceptance decision

**Decision: NOT ACCEPTED.** This draft contains no completed M10 live recovery,
installed-system, provider, or final repository evidence. Update the individual
rows only from reviewed current evidence. Change this decision only after every
required gate passes, cleanup is confirmed, and remaining risks are explicitly
accepted by the operator.
