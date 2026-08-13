# Milestone 10 security, backup, and operations acceptance

- **Review date:** 2026-08-12
- **Status:** Not accepted; implementation and evidence collection in progress
- **Implementation baseline:** `c66edf0`
- **Accepted source:** Pending final installed-system acceptance
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
| Architecture and threat decisions accepted | Review | Pending | ADRs 0027-0032 are accepted; final threat/runbook mapping review remains pending |
| Complete repository verification | Repository | Passed | `make PNPM='npx --yes pnpm@10.15.0' verify`: 1526 passed, 179 environment-gated skips; all remaining language/schema/plugin gates passed |
| Required PostgreSQL 17 integration gate | Durable local | Passed | Debian recovery LXC: 192 passed, zero skipped, PostgreSQL 17 |
| Production-relevant PITR durability | Durable local | Passed | Debian recovery LXC: production helper archive/restore path, 1 passed, zero skipped |
| Installed services and credentials hardened | Installed LXC | Pending | Exact installed units/credentials/hardening not yet audited |
| Encrypted base backup and WAL current | Installed LXC/storage | Pending | Verified complete chain not yet recorded |
| Isolated PostgreSQL PITR succeeds | Recovery drill | Passed (repository durability gate) | Disposable PostgreSQL 17 A/B-not-C recovery and corrupt manifest/ciphertext rejection passed; installed-storage drill remains pending |
| Primary Forgejo clean restore succeeds | Provider/recovery drill | Pending | Real read-only clone and restore not yet run/recorded |
| Secondary encrypted bundle restore succeeds | Offsite/recovery drill | Pending | Independent failure-domain drill not yet run/recorded |
| Archive continuation policy succeeds | Recovery drill | Pending | New-target reconstruction, verified remote promotion, and normal exporter append not yet run |
| Credential revoke/rotation bounds pass | Installed/provider | Pending | Per-class current gates not yet recorded |
| Privacy-safe observability and alerts pass | Repository/installed | Partial | Prometheus syntax and rule scenarios pass; installed delivery, fault injection, and canary scans pending |
| Leakage scanner detects every synthetic canary | Repository/durable local | Pending | Current complete scanner suite not yet recorded |
| Hard forget dominates all retained recovery copies | Durable local/recovery | Pending | Database/archive/key-backup non-resurrection pending |
| NPM/public-exposure boundary remains closed | Installed/external | Pending | Fresh generated-config and spoof/backend-counter proof pending |
| Drill cleanup completes | Installed/recovery | Pending | Exact cleanup inventory and second check pending |

The milestone remains **not accepted** while any required row is pending,
failed, or skipped.

## Architecture and threat decisions

Status: **ADRs accepted; final mapping review pending**.

ADRs 0027 through 0032 accept encrypted PostgreSQL PITR/recovery sets;
monotonic destruction across key backups; archive signer epochs, dual-signed
transition evidence, compromise cutoffs and new-target continuation; credential
lifecycle; privacy-safe telemetry, retention and evidence; and fail-closed
leakage scanning. Final acceptance still requires mapping every implementation
test and runbook to the active-topology threat matrix. Dormant relay,
node-agent, OAuth, public plugin/submission, and generic enrollment paths remain
non-applicable and unprovisioned.

## Repository verification

Status: **Passed for implementation baseline `c66edf0`**.

The complete verification command passed with 1526 Python tests passed and 179
environment-gated skips, followed by successful Go vet/tests, deterministic
protobuf verification, 11 schema validations, and plugin format, lint,
TypeScript, and six test gates. The local PostgreSQL skips were caused by the
missing `vector` extension and are superseded for the required database scope
by the zero-skip PostgreSQL 17 LXC result below. The separately gated PITR test
is likewise recorded below. Alert syntax/scenarios passed independently with
the installed `promtool`.

The current repository includes migration
`0011_observability_aggregates`, the least-privilege metrics/report role and
function boundary, the loopback metrics exporter, archive dual-signed
transition/compromise verification, and `continue-new-target`. The immutable
source archive checksum remains pending the final installed-system acceptance
candidate.

## Durable PostgreSQL 17 verification

Status: **Pending**.

The clean Debian gate must run with PostgreSQL 17 binaries explicitly selected
and database tests required:

```bash
SCALEVAULT_TEST_PG_BINDIR=/usr/lib/postgresql/17/bin \
SCALEVAULT_REQUIRE_DATABASE_TESTS=1 \
uv run --locked pytest tests/integration
```

The required database suite completed with 192 passed and zero skipped while
PostgreSQL 17 binaries were explicitly selected. It covered zero-to-head and
upgrade/downgrade migrations, metadata convergence, RLS and capability-role
denials, cross-tenant isolation, observability/report functions, archive
continuation checkpoint reconstruction, and destruction-ledger recovery.

The separate production-helper PITR test completed with one passed and zero
skipped. PostgreSQL continuously invoked the checked-in archive and restore
helper paths; recovery included the required A/B-not-C assertion and corrupt
manifest/ciphertext negative cases. This closes the repository durability
gate, not the installed backup-store, custody, timer, or offsite drill gates.

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
verification do not close the PITR drill below. Destructive retention is
architecture-blocked: the validation-only helper must report
`no_prune_dependency_watermark_absent` until authenticated PITR and exact
dependency/hold authority exist.

## PostgreSQL PITR drill

Status: **Repository durability drill passed; installed-storage drill pending**.

The disposable PostgreSQL 17 production-helper drill passed as described in
the durable verification section. Follow [PostgreSQL PITR](runbooks/postgresql-pitr.md)
on the installed encrypted backup and WAL stores before installed-system
acceptance. Record selected target
kind/value, achieved recovery point, timeline/system result codes, exact
migration and extension results, aggregate counts/digests, archive-prefix and
canary results, credential/destruction reconciliation, RPO/RTO, write-disable
proof, and cleanup confirmation.

## Primary Forgejo restore drill

Status: **Pending; not run or accepted by this record**.

Follow [Forgejo recovery](runbooks/forgejo-recovery.md). Record source head and
external head/manifest/high-water anchors, pinned-host-key result, signer epoch
public-key fingerprints, canonical transition-record and both detached-
signature results, compromise cutoff results when applicable, complete signed-
chain/manifest results, compatible revision, clean-destination preflight,
aggregate/canary results, archive-exclusion proof, RTO, and cleanup.

## Secondary encrypted bundle drill

Status: **Pending; not run or accepted by this record**.

Follow [Secondary-bundle recovery](runbooks/secondary-bundle-recovery.md).
Record the externally retained ciphertext digest, pre-decryption digest check,
authenticated decryption and `git bundle verify` result codes, exact ref/head,
signed-history and clean restore results, canaries, RTO, and verified removal of
every plaintext scratch object. The plaintext bundle digest remains protected
in-memory flow and is not retained. Do not record the private recovery identity.

## Archive continuation evidence

Status: **Pending**.

Record `new_immutable_archive_target_required` after clean restore; the exact
`continue-new-target` invocation and `verified_remote_promotion_required`
result; database/archive prefix equality; external head/manifest/high-water
anchors; byte-identical empty-target reconstruction; verified promotion to the
new immutable remote; and exactly one subsequent normal exporter first-parent
append. The continuation command itself must not sign, append, push, promote,
or activate the exporter. Existing-target re-anchor is not supported.
No checked-in production SSH-promotion command currently closes the next step;
remote promotion and normal exporter activation remain live/implementation
blockers. Divergence is preserved and fails the gate.

## Observability, alerts, and retention

Status: **Repository rule and database-boundary gates passed; live evidence pending**.

Record fixed-label/cardinality test results; Prometheus rule syntax and unit
tests; installed scrape and rule health; backup, WAL, offsite, archive, queue,
database, pool, storage, tunnel, credential, ingress, exposure, purge, and
recovery-drill alert fault injections; delivery outcomes; journald/NPM/
PostgreSQL/monitoring retention review; and root-only operator-report bounds.
Record migration `0011_observability_aggregates`; denial/isolation proofs for
both login/capability role pairs and fixed security-definer functions; the
dedicated `memory-metrics` exporter on `127.0.0.1:9098`; collector clear/down
behavior; and protected systemd report publication with no stdout.

Prometheus rule syntax and all checked-in rule scenarios passed with the
installed `promtool`. The PostgreSQL 17 suite also passed the function-only
metrics/report principals, owner-controlled tenant bindings, arbitrary-tenant
denial, payload/table denial, bounded report limits including NULL rejection,
and all nine report function families. These repository gates do not replace
installed scrape freshness, alert delivery, or operator-report publication.

Retention remains **pending** until operator-chosen byte caps are installed for
the 30-day journal/alert and 400-day content-free report maxima and the alert
receiver/handling policy is selected and verified. Repository defaults do not
supply those activation inputs.

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
rollback boundary, matched or extended its independently retained freshness
anchor, and dominated stale restored keys. Routine key-provider backup
activation remains blocked until the manifest/anchor and restore-reconciliation
contract passes live gates. It must not claim plaintext or Genesis compatibility
records were cryptographically erased, that unlink is physical sanitization, or
that unknown external copies do not exist.

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
