# Milestone 10 security, backup, and operations acceptance

- **Review date:** 2026-08-13
- **Status:** Not accepted; implementation and evidence collection in progress
- **Implementation baseline:** `368b302`
- **Frozen release:** `e5a6e90e4ef10d2316f1902aacf7533428d55e09`
- **Frozen release archive checksum:**
  `77b47fb145f852b7f43f7a6de69b7e9b46e83c3efdce0dd503a1f9a795d36184`
- **Evidence revision:** Pending evidence-only acceptance update
- **Database migration revision:** Candidate `0011_observability_aggregates`;
  installed preflight remains at `0010_ingress_provider_heads`

This is the final record structure required by the M10 plan. It deliberately
does not turn source implementation, unrun commands, or prior Milestone 9
evidence into M10 acceptance. Every required row remains pending until the
named frozen release, durable PostgreSQL 17, installed-host, and recovery gates
produce reviewed content-free evidence. Excluded and non-blocking rows are not
closure gates and must remain explicitly unevaluated unless separately tested.

The frozen release is the immutable source revision whose executable behavior,
configuration, migrations, generated artifacts, and source archive checksum are
installed and tested. The evidence revision is the later commit that records
reviewed bounded results. It may differ only by evidence and acceptance text
that cannot affect runtime behavior. Any executable, configuration, schema,
migration, generated-artifact, or dependency change creates a new release
candidate and requires a new freeze, checksum, installation, and applicable
reruns.

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
| Architecture and threat decisions accepted | Review | Passed | ADRs 0034 and 0035 are accepted and every active threat row maps implementation, tests, runbooks, and evidence |
| Complete repository verification | Repository | Passed | Frozen release passed 1,579 Python tests plus all Go, protobuf, schema, and plugin gates; deterministic source checksum independently matched |
| Required PostgreSQL 17 integration gate | Durable local | Partial | Baseline passed with 192 passed and zero skipped; final frozen-release rerun remains pending |
| Production-relevant PITR durability | Durable local | Partial | Baseline production-helper gate passed; final frozen-release rerun remains pending |
| Installed services and credentials hardened | Installed LXC | Pending | Read-only preflight found the prior `c95d66c` layout and migration `0010`; exact M10 installation and audit remain pending |
| Encrypted base backup and WAL current | Installed LXC/local recovery storage | Pending | Verified complete local chain not yet recorded; Backblaze transfer is operator-managed and non-blocking |
| No-prune recovery retention validates without deletion | Installed recovery storage | Pending | Fixed result, per-class before/after inventory equality, zero deletion attempts, unchanged restore points/holds, and capacity remain pending |
| Isolated PostgreSQL PITR succeeds | Recovery drill | Partial | Repository A/B-not-C gate passed; installed-storage drill remains pending |
| Primary Forgejo clean restore succeeds | Provider/recovery drill | Excluded / not evaluated | No Forgejo provider recovery claim is permitted for M10 |
| Secondary encrypted bundle restore succeeds | Local recovery drill | Partial | Same-anchor clean disposable-database restore is implemented; final PostgreSQL 17/`age` frozen-release rerun remains pending |
| Archive continuation policy succeeds | Recovery drill | Excluded / not evaluated | No reconstruction, promotion, continuation, or resumed-exporter claim is permitted for M10 |
| Credential revoke/rotation bounds pass | Installed/provider | Pending | Per-class current gates not yet recorded |
| Privacy-safe observability, alerts, reports, and caps pass | Repository/installed | Partial | All 38 rules and repository scenarios pass at the frozen release; production activation, fault recovery, reports, and enforced caps remain pending |
| Leakage scanners and cross-process canaries pass | Repository/durable local | Partial | Offline and protected operational scanners pass repository gates; installed captures, zero-match result, and cleanup remain pending |
| Hard forget dominates the accepted recovery boundary | Durable local/recovery | Partial | Composed requester/broker/anchor/stale-copy reconciliation passes in source; installed PITR non-resurrection remains pending |
| NPM/public-exposure boundary remains closed | Installed/external | Partial | Static checker/count contracts pass; external spoof/backend-counter/path/canary proof and cleanup remain pending |
| Drill cleanup completes | Installed/recovery | Pending | Exact cleanup inventory, expected production-state result, residue count, and independent second check remain pending |

The milestone remains **not accepted** while any required row is pending,
failed, or skipped.

## Architecture and threat decisions

Status: **Passed**.

ADRs 0027 through 0033 accept encrypted PostgreSQL PITR/recovery sets;
monotonic destruction across key backups; archive signer epochs, dual-signed
transition evidence, compromise cutoffs and new-target continuation; credential
lifecycle; privacy-safe telemetry, retention and evidence; and fail-closed
leakage scanning. ADR 0033 records operator-managed Backblaze custody and local
alert evaluation without requiring external notification delivery. ADRs 0034
and 0035 accept the narrowed local archive boundary and validation-only
no-prune posture. Every active-topology threat row maps its implementation,
tests, runbook, and bounded evidence class. Dormant relay, node-agent, OAuth,
public plugin/submission, and generic enrollment paths remain non-applicable
and unprovisioned.

## Repository verification

Status: **Passed at the frozen release**.

The complete verification command passed with 1,579 Python tests passed and 181
environment-gated skips, followed by successful Go vet/tests, deterministic
protobuf verification, 11 schema validations, and plugin format, lint,
TypeScript, and six test gates. The local PostgreSQL skips were caused by the
missing `vector` extension and are superseded for the required database scope
by the zero-skip PostgreSQL 17 LXC result below. The separately gated PITR test
is likewise recorded below. The M10 deployment lane passed 126 tests with only
the local `promtool` availability skip. The designated LXC's `promtool` loaded
all 38 frozen-release rules and passed every checked-in rule scenario.

The current repository includes migration
`0011_observability_aggregates`, the least-privilege metrics/report role and
function boundary, the loopback metrics exporter, archive dual-signed
transition/compromise verification, and `continue-new-target`. Those archive
continuation capabilities are not exercised or accepted by M10. A second raw
`git archive` digest independently matched the frozen checksum, and the release
manifest/tree immutability checks passed.

## Durable PostgreSQL 17 verification

Status: **Baseline passed on the designated Debian recovery LXC; final rerun pending**.

The clean Debian gate must run with PostgreSQL 17 binaries explicitly selected
and database tests required:

```bash
make test-m10-database-required
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
gate, not the installed backup-store, custody, or timer gates. Backblaze offsite
handling is an operator-managed concern and is not an M10 acceptance blocker.

## Read-only installed preflight

Status: **Preflight complete; mutation not authorized**.

The designated LXC is healthy on PostgreSQL 17.10 with `vector`, `pg_trgm`,
`citext`, and `pgcrypto`, and its canonical data directory is the expected
mounted path. It remains on the prior `c95d66c` release layout and migration
`0010_ingress_provider_heads`. Only the API unit is presently installed from
the M10 inventory; the M10 metrics, backup, retention, destruction, worker, and
timer units are absent. The three dedicated backup/staging/recovery mounts and
backup public recipient are absent, and no routine-node recovery private
identity is present. These are clean stop conditions, not failures or inferred
authorization. Phase 1 installation, a pre-upgrade recovery point, storage and
recipient provisioning, and an isolated recovery environment remain pending.

## Installed service and credential hardening

Status: **Pending live evidence**.

Follow [Installed-system verification](runbooks/installed-verification.md).
Record accepted unit and executable digests, exact enabled/disabled service
classes, timer status, reviewed systemd hardening, secret-delivery result,
listener class result, core-dump/log-retention result, and per-credential-class
revocation/rotation outcome. Do not include unit/environment contents or
provider responses.

Per-class evidence must cover direct Codex ingress; Secure MCP Tunnel; the
OpenAI association/control plane when provisioned; applicable PostgreSQL
application, metrics, report, worker, backup, and migration identities; backup
recipient/recovery-identity custody; sealed digest binding; Bearer HMAC or
client-token pepper; content-key authority; and optional GitHub ingress when
active. For rotatable credentials, record replacement, intended-operation
success, old-credential next-use rejection, old-session termination, provider
revocation when applicable, rollback posture, canary result, and cleanup.
For custody or recovery material that must remain valid for retained objects,
mark unsafe rotation/revocation fields not applicable and record custody,
availability, intended recovery use, canary absence, and cleanup instead.

## Encrypted base-backup and WAL evidence

Status: **Pending live evidence**.

Record safe base-backup object identifier, ciphertext/manifest digests,
completed/verified timestamps, WAL continuity result, recovery-window result,
retention decision, and confirmation that the routine
node did not contain the recovery private identity. Backup creation and
verification do not close the PITR drill below. Destructive retention is
architecture-blocked: the validation-only helper must report
`no_prune_dependency_watermark_absent` until authenticated PITR and exact
dependency/hold authority exist.

Backblaze is the operator-selected offsite destination. Provider-specific copy,
retention, freshness, and restore evidence remains useful operational evidence,
but is outside the M10 blocker set and is not required to change this record's
acceptance decision. Without that evidence, this record must not claim that an
independent Backblaze copy exists, is current, or was restored.

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

Status: **Excluded / not evaluated**.

Forgejo provider recovery, remote equality, target promotion, deploy-key and
host-key exercises, and provider API operations are outside M10. This record
makes no Forgejo restore or remote-custody claim. The historical
[Forgejo recovery](runbooks/forgejo-recovery.md) procedure is not an M10 gate.

## Secondary encrypted bundle drill

Status: **Partial; same-anchor clean database restore pending**.

The Debian recovery LXC created a real ephemeral SSH-signed archive history,
created an offsite-suitable full-history bundle, encrypted it to an ephemeral
`age` recipient, independently recomputed the ciphertext SHA-256, and
materialized it through the checked-in recovery CLI. The restored ref/head and
reachable object closure were byte-identical to the source, and signed-history
verification passed against the protected unpublished clone before atomic
publication. Wrong-identity and corrupted-ciphertext attempts returned only the
fixed safe failure and created no output repository. The gate removed the
ephemeral signing and recovery identities, plaintext bundle, scratch, source,
and restored repositories; the staging root was independently removed after
the run. This proves materialization and exact archive recovery only. M10 still
requires the materialized history to restore into a clean disposable database,
bound to the same source head, manifest, high-water mark, signer policy, and
object bytes. Until that passes at the frozen release, the bundle gate remains
partial.

Backblaze handles the offsite failure domain. Provider placement, freshness,
retention, and retrieval validation are operator-managed and non-blocking. In
their absence, do not claim that a provider copy exists or has been restored.

## Archive continuation evidence

Status: **Excluded / not evaluated**.

Archive checkpoint reconstruction, new-target continuation, remote promotion,
and subsequent exporter append are outside M10. No continuation command,
provider mutation, or exporter activation is required or authorized, and this
record makes no continuation or resumed-exporter claim.

## Observability, alerts, and retention

Status: **Repository/local evaluation passed; production activation pending**.

Record fixed-label/cardinality test results; Prometheus rule syntax and unit
tests; installed scrape and rule health; backup, WAL, archive, queue,
database, pool, storage, tunnel, credential, ingress, exposure, purge, and
recovery-drill alert fault injections; local pending/firing/recovery outcomes;
zero rule-evaluation errors; journald/NPM/
PostgreSQL/monitoring retention review; and root-only operator-report bounds.
Record migration `0011_observability_aggregates`; denial/isolation proofs for
both login/capability role pairs and fixed security-definer functions; the
dedicated `memory-metrics` exporter on `127.0.0.1:9098`; collector clear/down
behavior; and protected systemd report publication with no stdout.

Prometheus rule syntax and all checked-in rule scenarios passed with the
installed Debian `promtool`: all 38 rules loaded, and the fixtures exercised
exact threshold, pending, firing, recovery, absent-series, and scrape-down
behavior. An isolated Debian Prometheus process also reached ready state,
reported healthy evaluation with zero evaluation errors, and self-scraped with
`up=1`; its temporary listener, storage, and configuration were removed without
changing the production Prometheus process. The PostgreSQL 17 suite also passed
the function-only metrics/report principals, owner-controlled tenant bindings,
arbitrary-tenant denial, payload/table denial, bounded report limits including
NULL rejection, and all nine report function families. These repository gates
do not replace installed scrape freshness or operator-report publication.
External alert delivery is explicitly not required for M10; local rule evaluation and visible
collector/rule health remain required. When no receiver is configured, this
record must not claim notification delivery.

The production Prometheus process is healthy, but currently loads no ScaleVault
rule groups or ScaleVault scrape jobs. Installed production activation and
fault injection therefore remain pending even though the local evaluation gate
passes.

The checked-in Backblaze/offsite rule scenarios remain validated repository
contracts, but no installed provider-series producer or provider fault
injection is required for M10.

No-prune recovery retention remains **pending live evidence** until installed
inventory validation records exact before/after object counts and canonical
digests separately for bases, WAL/history, restore points, holds, verification
markers, indexes/manifests, and status artifacts; the fixed
`no_prune_dependency_watermark_absent` result; zero deletion attempts; unchanged
restore points and holds; and adequate capacity. This is a
validation-only success contract, not a blocked destructive-retention feature.
Operational retention caps remain separately pending until operator-chosen byte
caps are installed for the 30-day journal/alert and 400-day content-free report
maxima. No external alert receiver is required for M10.

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
PostgreSQL, the local key provider and its permitted backup, the independently
anchored destruction ledger, and installed PITR. Local signed-archive and
encrypted-bundle recovery are separate gates outside this erasure-dominance
claim. Acceptance is bounded to cryptographic erasure inside the tested copies.
Record that the independent
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
results; exact private/canonical listener result; each active non-Forgejo
credential class separately; GitHub provider gates only if the optional ingress
is provisioned; local monitoring and alert evaluation/recovery; age and byte-cap
results for each required retention class; offline and cross-process scanner
results; and cleanup plus independent second-check results. Forgejo recovery and
continuation are excluded and not evaluated. Backblaze operation and external
alert delivery are not M10 acceptance blockers. Their absence must not be
reported as successful offsite durability or notification delivery.

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
installed-system, or final frozen-release evidence. Update the individual rows
only from reviewed current evidence, record the later evidence-only revision
separately, and change this decision only after every required gate passes,
cleanup is confirmed, and remaining risks are explicitly accepted by the
operator.
