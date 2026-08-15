# ScaleVault Milestone 10 Remaining Gates Closeout Plan

- **Status:** Execution in progress; Phases 0 and 1 complete
- **Prepared:** 2026-08-12
- **Planning baseline:** `17c985a`
- **Historical planning input:**
  `Plans/Archives/SCALEVAULT_M10_SECURITY_BACKUP_OPERATIONS_PLAN.md`
- **Acceptance record:** `docs/milestone-10-acceptance-2026-08-12.md`
- **Target:** Private, single-owner ScaleVault deployment

## 1. Purpose

This tracked closeout plan, accepted ADRs 0034 through 0036, the tracked runbooks,
and the current acceptance record are the governing M10 execution authority.
The untracked archived plan named above and its untracked V2 roadmap are
preserved historical planning inputs only. They do not authorize live work,
reopen Forgejo or archive-continuation gates, or override this plan's narrowed
scope.

This plan closes the remaining Milestone 10 gates after repository
implementation, PostgreSQL 17 integration, production-helper PITR, encrypted
local bundle recovery, local alert-rule evaluation, architecture
reconciliation, and installed Phase 1 have passed.

The remaining work is installed-storage provisioning and recovery, live
security drills, production monitoring activation, installed scanner and NPM
proof, cleanup, and content-free evidence collection. The acceptance record is
authoritative for completed-gate status; stale planning-baseline counts below
remain historical context rather than instructions to recreate evidence.

Forgejo operations and archive continuation are explicitly excluded. Milestone
10 will not require or perform a Forgejo provider restore, local or remote
target promotion, deploy-key or host-key exercise, provider API operation, or
production exporter reactivation. Local signed-Git verification and encrypted
bundle recovery remain in scope because they protect the archive format and
recovery semantics independently of any hosting provider.

This plan does not itself authorize mutation of the installed LXC, NPM,
PostgreSQL cluster, monitoring configuration, credential provider, backup
store, or key-provider store. Each live phase begins with its listed operator
checkpoint and stop conditions.

## 2. Accepted evidence at the planning baseline (historical)

The following evidence is already recorded and does not need to be recreated
merely to start closeout:

| Gate | Accepted result |
|---|---|
| Complete repository verification | 1,526 Python tests passed; remaining language, schema, and plugin gates passed |
| PostgreSQL 17 integration | 192 passed, zero skipped, on the Debian recovery LXC |
| Production-helper PITR | One passed, zero skipped, with continuous helper archive/restore use, A/B-not-C recovery, and corruption negatives |
| Encrypted local archive bundle materialization | Passed with real `age`, exact signed-history/object equality, wrong-identity and corrupt-ciphertext rejection, and cleanup; same-anchor database restore remains pending |
| Alert rule source validation | All 38 rules loaded and pending, firing, recovery, missing-series, and scrape-down fixtures passed |
| Isolated Prometheus evaluation | Ready, healthy self-scrape, expected rule vector, and zero evaluation failures |

These results prove the repository and disposable recovery paths at their
recorded revisions. They do not prove the currently installed release,
installed backup store, production Prometheus configuration, current
credentials, NPM exposure boundary, or cleanup state.

The complete repository gate and immutable source checksum are already accepted
for frozen release `73814b6`. A later evidence-only revision does not become a
new runtime candidate and does not require that gate to be rerun. If executable
behavior, checked-in deployment configuration, schema, migration, generated
artifacts, or dependencies change, freeze the reviewed descendant, preserve a
new immutable source checksum, and rerun every applicable repository and
installed gate before acceptance.

## 3. Scope

### 3.1 Required closeout work

Items 1 through 4 are completed foundations recorded in the acceptance record.
Remaining live execution resumes with the prerequisite authorization for item 5;
their presence here preserves the full dependency chain and does not authorize
their repetition.

1. Accept architecture amendments for the Forgejo exclusion and M10 no-prune
   retention posture.
2. Reconcile the threat model, runbooks, deployment documentation, and
   acceptance record with those amendments.
3. Install an immutable current release in the designated LXC with migration
   `0011_observability_aggregates` and all accepted units, scripts, and
   hardening.
4. Audit installed credentials, service privileges, listeners, mounts, core
   dumps, journal policy, and disabled surfaces.
5. Produce and verify one current encrypted PostgreSQL base-backup and
   continuous WAL chain using the installed helper.
6. Restore that installed chain into an isolated PostgreSQL 17 instance and
   prove the selected recovery point, compatibility, RPO/RTO, credential
   posture, destruction-ledger reconciliation, and cleanup.
7. Exercise active non-Forgejo credential rotation and revocation paths.
8. Prove backup-aware hard forget and stale-key non-resurrection across the
   local key-provider and installed-PITR boundary accepted by ADR 0034.
9. Activate the production-local metrics exporter, Prometheus scrape job and
   rules, protected operator reports, byte caps, and required local fault
   injections.
10. Run the leakage scanner and cross-process canary checks against the exact
    installed candidate artifacts and operational outputs.
11. Refresh the NPM external exposure, spoof rejection, and backend-counter
    proof.
12. Clean every drill artifact, perform an independent second check, and update
    the acceptance record from exact content-free evidence.

### 3.2 Explicit non-goals

The following are not Milestone 10 blockers and must not be performed under
this plan:

- Forgejo provider/API operations;
- live Forgejo clone, fetch, push, restore, target creation, or promotion;
- Forgejo deploy-key, host-key, administrator, or recovery-identity work;
- production archive-exporter activation against a Forgejo remote;
- archive checkpoint reconstruction, continuation, or subsequent exporter
  append acceptance;
- existing-target archive re-anchoring;
- Backblaze placement, freshness, retention, retrieval, or deletion evidence;
- external alert receivers, routing, or notification-delivery proof;
- destructive backup pruning;
- public export, public repository, branch/copy-on-write, descendant, or
  publication work assigned to Milestone 11; and
- claims about erasure of unknown third-party copies or physical media.

Backblaze remains the operator-managed offsite destination. The local system
must still produce exact encrypted objects and restore them with an
independently supplied identity, but this plan neither configures Backblaze nor
claims that an offsite copy exists.

External alert delivery is optional. Local scrape health, rule health,
pending/firing/recovery behavior, evaluation-error visibility, and protected
operator access remain mandatory.

### 3.3 Forgejo no-claim boundary

Removing Forgejo from the closeout does not prove it works and does not remove
Forgejo from all product history. Final M10 evidence may claim only that local
signed-archive and encrypted-bundle recovery were verified. It must not claim
that:

- a Forgejo instance was restored;
- a Forgejo remote contains the accepted history;
- a remote target was promoted;
- Forgejo credentials or host keys were validated; or
- any exporter checkpoint was reconstructed or any production exporter
  resumed.

## 4. Closeout invariants

1. PostgreSQL remains the semantic source of truth.
2. Local signed-Git recovery verifies externally anchored head, manifest,
   high-water mark, signer epoch, and, when applicable, transitions and
   compromise cutoffs.
3. Recovery never overlays an active database, key-provider store, or
   production data directory.
4. API, ingress, tunnel, workers, pollers, exporter, and destructive services
   remain disabled during recovery until their explicit reactivation gate.
5. Restored database credentials, bearer metadata, or content keys do not
   automatically regain authority.
6. Backup private identities, content DEKs, bearer peppers, signer private
   keys, and database credentials are not stored with the objects they protect.
7. The routine backup node receives only an `age` public recipient; the private
   recovery identity is supplied only to the isolated recovery environment.
8. The independent destruction ledger and its accepted freshness anchor are
   never rolled back with the key-provider backup.
9. M10 retention has zero destructive authority. Ambiguity, missing evidence,
   or capacity pressure stops the operation and never authorizes pruning.
10. Metrics, alerts, logs, reports, and evidence contain no memory payload,
    authorization value, credential value, private endpoint, or unbounded
    identifier.
11. No required gate is converted from `pending` to `pass` by source presence,
    a skipped test, a mocked provider, or an unexecuted command.
12. Cleanup failure prevents acceptance.

## 5. Execution order

```text
Architecture amendments
  -> acceptance and threat-model reconciliation
  -> immutable candidate installation and installed audit
  -> encrypted base/WAL production
  -> installed-store PITR
  -> credential and hard-forget drills
  -> production monitoring and local alert drills
  -> scanner and NPM exposure gates
  -> cleanup, final verification, and acceptance decision
```

Phases may prepare independent test data in parallel, but the installed-store
PITR, credential, hard-forget, monitoring, scanner, and NPM results must all
refer to the same accepted installed candidate or an explicitly reviewed
descendant with a new immutable checksum.

## 6. Phase 0: Freeze the narrowed architecture

### 6.1 ADR 0034: local signed-archive M10 acceptance

Accept a focused amendment to ADRs 0028, 0029, 0030, and 0033 that freezes the
following:

- Forgejo-specific recovery, archive continuation, credentials, provider
  evidence, checkpoint reconstruction, and exporter reactivation are excluded
  from M10.
- Archive correctness remains provider-independent and required: external
  anchors, signer fingerprints, bounded complete history verification, clean
  local restore, and encrypted bundle recovery. Dual-signed transition and
  exact compromise-cutoff evidence is required only when the accepted signer
  policy contains a transition or compromise declaration.
- No local test-only Git appender or direct `update-ref` operation is accepted
  as production continuation evidence.
- No continuation, remote equality, promotion, or resumed-exporter claim is
  made in M10. Existing-target re-anchor remains unsupported.
- Encrypted-bundle recovery must either restore the materialized history into a
  clean disposable database or compose two proofs bound to the exact same
  head, manifest, high-water mark, signer policy, and object bytes. The M10
  closeout selects the direct disposable-database restore and makes no installed
  archive cadence claim.
- The M10 hard-forget claim covers canonical PostgreSQL, the local key
  provider, the independently anchored destruction ledger, and installed PITR.
  Local signed-archive and bundle recovery remain separate format/recovery
  gates and are excluded from the erasure-dominance claim while archive export
  is disabled. M10 does not require a post-purge archive completion event and
  does not claim archive continuation.
- The acceptance record reports the Forgejo provider path as excluded and
  unverified, never passed.

Existing local signed-history and encrypted-bundle tests may satisfy the
provider-independent recovery gate only after the amendment is accepted and
their exact final-candidate result is recorded. No remote URI, remote
credential, provider operation, continuation adapter, or exporter activation
is needed.

### 6.2 ADR 0035: no-prune recovery retention

Accept a separate amendment to ADR 0027:

- the M10 retention helper has zero deletion authority;
- every base, WAL/history object, restore point, and hold is retained;
- eight daily and five weekly generations are accumulation and inventory
  floors, not deletion authority or an elapsed-time acceptance delay;
- installed inventory validation and capacity alerts are mandatory;
- the exact successful status is
  `no_prune_dependency_watermark_absent`;
- malformed, missing, corrupt, or ambiguous inventory fails closed;
- manual pruning and inferred dependency graphs are forbidden; and
- any later deletion requires a new ADR defining the evidence producer,
  independently held verification root, canonical signed schema, freshness and
  replay rules, custody and rotation, compromise handling, dependency graph,
  and exact deletion authorization.

`age` encryption authenticates ciphertext integrity to its recipient; it does
not identify an authorized producer of deletion evidence. Do not introduce a
speculative recovery catalog or signer in M10.

### 6.3 ADR 0036: single-NFS recovery store and local scratch

Accept the deployed storage constraint without manufacturing additional
mounts:

- `/mnt/memory` is the sole exact M10 storage mount;
- canonical PostgreSQL data and the encrypted local recovery store reside in
  separate permission-bounded directories on that mount;
- plaintext backup staging and isolated recovery scratch reside under their
  exact local `/var/lib/kivra-memory` roots and are never durable recovery
  objects;
- shared mount and dataset placement provides no independent failure domain,
  capacity pool, or dataset-loss RPO claim;
- no-prune retention and capacity validation remain mandatory;
- the private recovery identity remains outside the routine node and every
  backup object; and
- nightly NAS protection and NAS-to-Backblaze upload remain operator-managed,
  with no M10 application-consistency, freshness, or restore claim.

### 6.4 Documentation reconciliation

After all three amendments are accepted:

- update the ADR index and supersession headers;
- update the M10 acceptance matrix and narrative;
- remove Forgejo gates from installed verification, credential, hard-forget,
  shutdown/startup, recovery, and cleanup procedures;
- remove archive continuation, checkpoint reconstruction, and normal exporter
  append from the M10 blocker matrix;
- retain the Forgejo runbook only as non-M10 historical or future guidance;
- map every active threat row to its implementation, test, runbook, and
  evidence class;
- change destructive retention from `pending` to the accepted no-prune gate;
- update the installed-evidence template so Forgejo restore, remote promotion,
  and exporter-append fields are `excluded / not evaluated` rather than
  pending;
  and
- preserve explicit no-claim language for Forgejo, Backblaze, and external
  alert delivery.

### 6.5 Phase exit

- ADRs 0034 through 0036 are accepted.
- All affected policy and operations documents agree.
- No M10 matrix row still requires Forgejo, archive continuation, or
  destructive pruning.
- Link, fence, formatting, and content-boundary checks pass.

## 7. Phase 1: Install and freeze the acceptance candidate

### 7.1 Preflight and authorization

Record, without private coordinates or secret values:

- source revision and clean/known worktree state;
- immutable source archive SHA-256;
- currently installed revision and migration;
- available rollback release and database recovery point;
- required mounts and free space;
- PostgreSQL 17 and extension availability;
- exact unit/timer enablement changes; and
- maintenance-window authorization.

The approval must name the exact versioned release destination, release
pointer, package/install roots, unit/config destinations, database and current
migration, role/grant bootstrap, tenant-binding rows, services to quiesce, and
allowed enable/disable operations. Stop writers and take the accepted database
recovery point before schema or grant mutation. Authorized writes are limited
to those named targets.

Stop on a source/digest mismatch, dirty or mixed release, failed service
quiescence, migration/role drift, unexpected listener, inadequate recovery
point, or any need to touch an unnamed path or role. Application rollback may
restore the prior immutable release pointer only when its migration
compatibility is verified. Database downgrade is not authorized by this plan;
use a reviewed forward repair or obtain separate downgrade/recovery approval.

The acceptance record now binds the installed release to frozen candidate
`73814b6` and migration `0011_observability_aggregates`. Do not reinstall Phase
1 or treat a later evidence-only revision as the installed runtime. Stop if live
inventory no longer matches that frozen candidate or if source and installed
revisions are mixed.

### 7.2 Install

Install one versioned immutable candidate and atomically update the reviewed
release pointer. Install the exact checked-in:

- application package and console entry points;
- migration through `0011_observability_aggregates`;
- PostgreSQL role bootstrap and tenant-binding script;
- service, path, and timer units;
- backup, NPM, tunnel, restore-reconcile, report, and monitoring helpers;
- Prometheus rule and scrape examples adapted only through reviewed local
  configuration; and
- runbooks and content-free evidence template.

Do not place a secret in a source tree, environment file, command line,
journal, evidence record, or immutable release directory.

### 7.3 Installed-system audit

Verify and record fixed results for:

- release revision, source checksum, migration head, executable digests, and
  unit digests;
- enabled and disabled services, paths, timers, and their service accounts;
- `systemd-analyze verify` and reviewed `systemd-analyze security` exceptions;
- credential name, owner, mode, link-count, size bound, and consumer unit,
  never credential content;
- exact read/write paths and absence of unrelated writable paths;
- core-dump suppression, proxy-environment clearing, restart bounds, task,
  memory, and CPU limits;
- local-only PostgreSQL, API, metrics, and report surfaces;
- the exact private ingress listener behind NPM;
- routine-node absence of the backup private identity; and
- absence or disablement of relay, node-agent, OAuth, public plugin,
  publication, and other dormant surfaces.

Before creating an acceptance backup, establish and verify the database
authorization boundary in this exact order:

1. run the reviewed role bootstrap to converge pre-migration memberships and
   grants;
2. migrate through `0011_observability_aggregates`;
3. rerun the role bootstrap so new functions and capabilities converge;
4. use the owner-only binding script to bind both fixed metrics and report
   wrapper logins to their exact tenant before either service is enabled,
   without placing the tenant or credential in argv;
5. verify wrapper and capability role membership, function EXECUTE grants, and
   `PUBLIC` revocation;
6. prove direct table/sequence access, mutation, payload reads, binding-table
   access, and arbitrary-tenant function calls fail; and
7. execute the metrics snapshot and all nine bounded report function families,
   including NULL/zero/over-limit rejection.

Failure of this boundary stops backup and later drills; an installed database
with unconverged grants must not become the M10 recovery baseline.

Optional GitHub ingress is `not-applicable` only if the service is disabled and
its provider token and local installation authority are unprovisioned or
revoked. Otherwise its existing provider/local revocation gate remains
required because it is an active ingress, not because of Forgejo.

### 7.4 Phase exit

- One immutable installed revision matches the frozen release. A later
  evidence revision may differ only by bounded evidence, acceptance, and
  closeout-authority text that cannot affect runtime behavior.
- Migration `0011`, owner-controlled tenant bindings, and the tested database
  capability boundaries are installed.
- No unit or credential has unexplained privilege.
- Rollback remains available and no unexpected listener is present.

## 8. Phase 2: Produce an installed encrypted PostgreSQL recovery chain

### 8.1 Authorization checkpoint

The installed Phase 1 record leaves the encrypted recovery-store directories,
local plaintext scratch roots, backup public recipient, and sealed-content
deployment absent. ADR 0036 accepts the existing `/mnt/memory` NFS mount as the
sole M10 storage mount; no additional `/mnt` mount is required or expected.
Naming a fixture or directory does not authorize provisioning it. Before any
backup or synthetic sealed mutation, obtain approval that expressly names:

- the existing `/mnt/memory` mount, the exact encrypted store and bounded
  writable status/verification directories beneath
  `/mnt/memory/kivra-memory/backups/postgresql-pitr`, the local plaintext
  staging root `/var/lib/kivra-memory/backup-staging`, and the isolated
  recovery root `/var/lib/kivra-memory/recovery`, including owner, mode, and
  allowed capacity change;
- the public `age` recipient credential source and installed destination on the
  routine node, plus the independently controlled private-identity source and
  its permitted staging boundary;
- the exact isolated recovery host/environment, its read-only access to the
  accepted encrypted store, its local recovery root, service account,
  verification units, listener prohibition, and teardown boundary;
- the PostgreSQL cluster, helper revision, `memory_backup` role and exact
  grants, protected pgpass credential, `pg_hba.conf` rows, secret-free recovery
  configuration digest, archive configuration, controlled PostgreSQL restart,
  units/timers, capacity budget, maintenance window, and pre-change rollback
  state; and
- the synthetic sealed tenant/scope, one disposable activation-preflight
  fixture, the distinct retained Phase 2 correlation fixture, provider
  control/material roots, destruction ledger and both anchor locations, request
  root, digest-binding and accepted-anchor credential sources, required
  accounts/groups, API and ingress drop-ins, internal-service identity, broker
  path/service, purge worker, restore-reconcile unit, pre-forget provider-copy
  root, and the exact enable/restart operations.

Authorized mutations are limited to those explicitly named provisioning
targets, the two named synthetic fixtures, the reviewed archive configuration,
local encrypted backup/WAL/status objects, the drill-owned provider copy, and
named unit/timer state. Sealed provisioning must follow the checked-in optional
sealed-content deployment contract and pass its disposable
create/read/hard-forget activation preflight. The destroyed preflight fixture
must not be reused as the distinct retained Phase 2 correlation fixture. On
failure, disable the new timers/archive command and sealed drill units as
directed by their runbooks, preserve already durable encrypted objects and
independent destruction authority, remove only incomplete owned staging, and
do not delete a previously accepted recovery object.

### 8.2 Custody and storage preflight

- Provision only the public `age` recipient on the routine backup node.
- Keep the private recovery identity outside that node and outside every
  backup object.
- Verify `/mnt/memory` is the sole exact storage mount and verify the encrypted
  store, WAL, status, verification, local staging, and isolated recovery
  directory ownership and modes against the checked-in contracts.
- Verify the local staging and isolated recovery roots are empty, are not
  mounts, are outside `/mnt`, and are unavailable to routine application
  writers. The recovery environment may read accepted encrypted objects but
  may write only its exact bounded status/verification paths in that store.
- Confirm sufficient capacity for no-prune retention on `/mnt/memory` once;
  database, WAL, and backup labels are views of the same capacity pool and
  must not be summed.
- Record that the encrypted store and canonical PostgreSQL data share the NAS
  dataset and therefore share capacity, outage, corruption, and dataset-loss
  fate. Nightly NAS protection is operator-managed and is not an
  application-consistent PITR or restored-copy claim without separate
  evidence.

### 8.3 Produce and verify

Using the installed helper and PostgreSQL 17 configuration:

1. Create the exact synthetic envelope-encrypted record through the canonical
   handler before the accepted base backup. Record a domain-separated
   content-free correlation digest binding the synthetic database ciphertext,
   its external key reference, and the drill generation without recording any
   identifier or key material.
2. Create a bounded pre-forget provider control/material backup for that exact
   synthetic key. Record its canonical inventory digest and prove it excludes
   the destruction ledger and both anchor copies.
3. Enable continuous WAL archival through the checked-in archive command.
4. Produce one full physical base backup containing the correlated synthetic
   ciphertext and advance WAL so the chosen recovery target also contains it.
5. Validate `pg_verifybackup`, encrypted manifests, ciphertext digests,
   timeline/history objects, atomic publication, and staging cleanup.
6. Advance the database sufficiently to archive and verify subsequent WAL.
7. Record the safe base identifier, bounded digests, creation/verification
   timestamps, continuous-window result, timer results, and capacity headroom.
8. Bind the base ID, target/recovery window, provider-backup digest, and
   synthetic correlation digest in the protected drill manifest.
9. Before retention validation, record bounded counts and canonical inventory
   digests separately for base objects, WAL/history objects, restore points,
   holds, verification markers, indexes/manifests, and status artifacts.
10. Run retention validation and prove it returns
   `no_prune_dependency_watermark_absent` without deleting or altering any
   object, marker, restore point, or hold.
11. Recompute the same counts and inventory digests and require exact equality,
   except for an explicitly expected new content-free validation status artifact
   whose prior absence and final digest are separately recorded.

Do not wait for, configure, or inspect Backblaze as part of this phase.

### 8.4 Stop conditions

Stop on a missing or wrong recipient, private identity on the routine node,
unexpected ownership or mode, incomplete WAL continuity, manifest mismatch,
unstable source file, staging residue, insufficient no-prune capacity, or any
attempted deletion.

### 8.5 Phase exit

- A current installed encrypted base/WAL chain is locally verified.
- The routine node cannot decrypt it.
- Retention is proven validation-only and capacity remains acceptable.

## 9. Phase 3: Restore the installed chain with PostgreSQL 17

### 9.1 Authorization checkpoint

Obtain approval for the exact backup generation, target selector, disposable
local recovery root, recovery service account, private-identity credential
source, listener/socket class, and maximum drill duration. Inventory the empty
target and all processes using the accepted encrypted store before mutation.
Authorized writes are confined to that local recovery root, the exact bounded
verification/status paths, and protected drill evidence. Rollback is teardown
of the isolated instance and removal of drill-owned plaintext/scratch
artifacts; promotion or overlay of production is not authorized.

### 9.2 Isolation

- Stop all ScaleVault writers, ingress paths, workers, pollers, exporters, and
  destructive services in the recovery environment.
- Use a disposable empty local recovery root outside `/mnt` and a local-only
  socket/port.
- Supply the private `age` identity only through the protected recovery
  credential boundary.
- Select a target that proves state A and B are present while later state C is
  absent.

### 9.3 Production-path drill

Use the installed backup helper without replacing its generated
`restore_command`. Verify:

- exact PostgreSQL system identifier, target and timeline;
- exact migration revision and extension set;
- event/global sequence and hash-chain integrity;
- projection high-water marks and aggregate counts/digests;
- content-free database recovery anchors and aggregate integrity, without
  requiring a live or current archive-exporter head;
- projection rebuild and embedding requeue behavior;
- post-target credential rotation/revocation review;
- current destruction-ledger anchor and stale-key reconciliation before any
  application read;
- exact presence of the synthetic correlation bound to the selected
  pre-forget base/WAL and provider-backup fixtures;
- corrupt manifest and ciphertext rejection;
- achieved recovery point, RPO against 15 minutes, and RTO against four hours;
  and
- write-disable and listener isolation throughout the drill.

Repository PITR evidence remains useful but does not substitute for this exact
installed-store drill.

### 9.4 Cleanup and exit

Stop the disposable PostgreSQL instance, remove the staged recovery identity,
decrypted data, scratch configuration, sockets, and temporary credentials, and
perform a second absence check.

Preserve the exact encrypted base/WAL chain, protected drill manifest, and
pre-forget provider-backup fixture for Phase 5. The decrypted Phase 3 database
is not retained and must not be referenced as later evidence.

This phase passes only if A/B-not-C, integrity, compatibility, credential,
destruction, RPO/RTO, and cleanup results all pass.

## 10. Phase 4: Close credential lifecycle gates

### 10.1 Authorization checkpoint

For each credential class, obtain separate approval naming the provider or
local authority, consumer units, exact old public identifier, replacement
scope, revocation action, session-termination expectation, maintenance window,
and rollback/recovery posture. Never group unrelated credentials into one
implicit authorization. Stop before revocation unless the replacement has
passed its bounded intended-operation probe. If replacement fails, restore
only the documented prior local configuration while it remains valid; never
re-enable a credential after provider revocation.

Classify every active non-Forgejo credential as `rotatable` or
`custody-recovery` before mutation. For a rotatable class, record the public
class name, consumer units, issue/replace/revoke timestamps, fixed
intended-operation result, fixed old-credential rejection result, old-session
termination posture, rollback posture, canary result, and cleanup result. Never
record the value.

For a custody/recovery class that must remain available for retained objects or
requires a separately reviewed migration, do not force rotation merely to
produce evidence. Mark unsafe replacement, revocation, next-use rejection, and
session fields `not-applicable`; instead record custody separation,
availability, intended recovery use, recovery dependency, canary absence, and
cleanup. This applies in particular to retained backup-recipient identities,
the sealed digest binder, and per-memory DEK authority. A class does not remain
pending solely because an unsafe lifecycle action is correctly not applicable.

Required active classes are:

- direct Codex ingress bearer;
- ScaleVault Secure MCP Tunnel bearer;
- OpenAI association/control-plane credential when provisioned;
- PostgreSQL application, metrics, report, worker, backup, and migration
  credentials as applicable;
- backup public-recipient and private-identity custody boundaries;
- sealed digest-binding credential, Bearer HMAC/client-token pepper, and
  content-key authority; and
- GitHub provider/local installation credentials only if the optional GitHub
  ingress is active.

Archive signer verification remains in scope through public trust material.
This plan does not provision, invoke, rotate, or revoke an archive signing
private key. A live signer rotation or compromise exercise requires separate
authorization and is required only when the accepted signer policy declares
that transition or compromise.

Verify replacement works, the old credential fails at its next defined use,
provider revocation is observed where applicable, stale sessions cannot write,
and logs/reports contain no credential canary. A single-pepper maintenance
rotation must be treated as a planned reissue/restart boundary, not a seamless
dual-pepper cutover.

### 10.2 Cleanup and exit

Remove superseded local credential files, temporary probes, staged replacement
material, and drill sessions according to each authority's runbook. Recheck
that only the intended current credential is available to each consumer and
that no revoked credential was restored. A rotatable class without replacement,
next-use rejection, provider result when applicable, and cleanup evidence
remains pending. A custody/recovery class remains pending until its custody,
availability, intended-use, canary, and cleanup evidence passes.

## 11. Phase 5: Prove backup-aware hard forget

### 11.1 Preconditions

Obtain approval for the exact synthetic content-key identity, PostgreSQL
tenant/test scope, request root, provider control/material roots, destruction
ledger and anchor generation, exact protected drill manifest, pre-forget
provider-backup digest, base/WAL identifiers, target selector, synthetic
correlation digest, and scratch/output roots. Confirm all content is synthetic and
that the irreversible mutation cannot select a production memory. Authorized
mutations are limited to that synthetic identity, its immutable destruction
fact, and drill-owned recovery destinations. Stop on any identity mismatch,
stale/unaccepted anchor, non-synthetic target, broker capability drift, or
cleanup ambiguity.

- The independently retained destruction anchor exactly authorizes the current
  ledger head.
- API and ingress have read-only destruction authority.
- The purge requester can only publish bounded requests.
- The dedicated non-root destruction broker has append/unlink authority but
  cannot read mode-`0600` DEKs or unrelated credentials.
- Key-provider backups exclude the destruction ledger and its external anchor.

### 11.2 Drill

Using synthetic envelope-encrypted content:

1. Submit selection and hard-forget through the real PostgreSQL outbox and
   installed request path.
2. Let the broker validate the request and publish the authoritative ledger
   fact plus new local anchor. At this point the operation must remain
   `purge_pending`; no erasure completion may be recorded.
3. Independently verify and retain the exact new anchor, install it as the
   accepted anchor credential, and restart the broker/API/ingress/purge-worker
   consumers that receive that credential.
4. Retry the pending purge. Verify the provider tombstone, absent active
   control/material, derived cleanup, and only then the canonical
   `cryptographically_erased` completion.
5. Verify the stale provider-backup inventory and synthetic correlation digest
   exactly match the Phase 2 protected drill manifest, then restore that backup
   into a fresh isolated provider root while retaining the current independent
   ledger and newly accepted anchor.
6. Run the restore-reconcile service before API or worker activation.
7. Verify the stale material and active control are removed, the exact
   tombstone is present, and reads remain impossible.
8. Create a fresh isolated PITR database from the exact Phase 2 base/WAL chain
   and target bound by the protected drill manifest. Prove the synthetic
   ciphertext correlation is present, attach only the reconciled provider root
   plus current ledger/accepted anchor, and verify the ciphertext remains
   unreadable before any application service is allowed to start.

Because archive export and continuation are excluded, this drill does not
require a new post-purge archive commit or archive completion event. ADR 0034
must accept that narrowed claim before the result can pass. It does not prove
archive or secondary-copy erasure dominance, post-purge archive agreement,
exporter continuation, or remote provider state. Local signed-history and
encrypted-bundle recovery remain separate gates with no erasure claim.

If routine key-provider backup is not enabled, prove it remains disabled and
mark only that backup-specific branch `not-applicable`. The installed hard
forget, ledger, broker, anchor, and restore-reconciliation gates remain
required.

Claims remain limited to envelope-encrypted data in the copies actually
tested. Do not claim plaintext/Genesis erasure, physical sanitization, or
deletion from unknown copies.

Remove synthetic database state where policy permits, stale-backup fixtures,
decrypted recovery destinations, archive/bundle scratch space, and temporary
credentials. Preserve the authoritative destruction fact and independently
accepted anchor. A second check must find no readable synthetic key material.

## 12. Phase 6: Activate local production observability

### 12.1 Authorization checkpoint

Obtain approval for the exact migration/bootstrap revision, wrapper logins,
tenant binding, exporter/listener, Prometheus configuration and rule files,
report output root, retention byte caps, injected fault cases, and service
enablement. Capture the prior local scrape/rule configuration and unit state
for rollback. Faults must be synthetic, bounded, individually reversible, and
must not corrupt canonical data or interrupt unrelated monitoring. On an
unexpected evaluation error, payload-bearing output, or unhealthy unrelated
target, stop injection, restore the prior configuration, and retain only fixed
content-free diagnostics.

### 12.2 Database and exporter boundary

Verify migration `0011` in the installed database:

- the two wrapper logins can set only their intended `NOLOGIN NOINHERIT`
  capabilities;
- capability roles have no table or sequence privileges;
- only reviewed `SECURITY DEFINER` functions are executable;
- `PUBLIC`, direct table reads, mutation, payload reads, and arbitrary-tenant
  access are denied;
- owner-controlled login-to-tenant bindings cannot be read or changed by the
  wrapper logins; and
- all report functions enforce the 1..500 row bound, including NULL rejection.

Install and enable the dedicated metrics exporter as
`memory-metrics:memory-metrics` on exactly `127.0.0.1:9098`, with protected
database and tenant credentials, a 30-second refresh, 10-second query timeout,
and bounded HTTP resources. On collector failure it must clear prior
DB-derived samples, set collector health down, and publish no raw exception.

### 12.3 Prometheus and alerts

- Install the dedicated ScaleVault scrape job and all checked-in rules.
- Confirm current scrape targets, rule groups, and evaluation-error count.
- Do not configure or test an external receiver.
- Treat Backblaze/offsite-only series as optional and do not require a producer.
- Inject each locally applicable failure using synthetic or disposable state,
  never by corrupting production data.
- Record threshold, pending, firing, recovery, missing-series, and scrape-down
  results with zero rule evaluation errors.
- Include collector stall/failure, base/WAL freshness, storage capacity,
  PostgreSQL, queue, local archive, pool, tunnel, credential, ingress,
  exposure, purge, and recovery-drill families applicable to the installation.

### 12.4 Reports and retention limits

- Generate a report through the hardened systemd template.
- Verify the dedicated report login and tenant binding.
- Verify exactly one new root-only mode-`0600` artifact below the protected
  output root.
- Verify no report content appears on stdout or in the journal.
- Install 30-day maxima for journal/alert data and 400-day maxima for
  content-free recovery/acceptance reports, each with an operator-chosen byte
  cap.
- Record age and byte-cap results, or an explicit reviewed `not-applicable`,
  separately for application/service journals, PostgreSQL logs, tunnel JSON,
  NPM/container logs, Prometheus monitoring history, local alert state, and
  protected operator/recovery/acceptance reports.
- Verify expiration and byte-cap behavior using synthetic artifacts.

### 12.5 Phase exit

Production-local scraping and rules are healthy, every applicable fault
enters and leaves the expected state, reports are protected, byte caps are
active, and no external-delivery claim is made.

Remove every synthetic fault and temporary monitoring artifact, restore normal
collector inputs, and verify all affected local alerts recover. Retain only the
protected bounded report and content-free acceptance evidence selected by the
operator.

## 13. Phase 7: Run installed leakage and canary gates

### 13.1 Authorization checkpoint

Obtain approval for the exact synthetic canary set, root-owned input path,
candidate artifact roots, operational outputs to inspect, protected result
destination, and cleanup inventory. Confirm no real credential or memory
payload is used as a canary. Authorized mutations are limited to named
synthetic candidate fixtures and bounded canary-bearing requests in the
approved drill scope. Stop immediately on a match outside that scope, scanner
incompleteness, unsafe filesystem provenance, or evidence containing matched
bytes; preserve only fixed counts and result codes.

### 13.2 Offline artifact scanner

Create root-owned mode-`0600` synthetic canary input and scan exact bounded
candidate directories. Retain only:

- `ok`;
- `artifact_sha256`; and
- fixed `counts`.

Exercise clean input and every required negative class: raw, NFC/NFKC,
Base64, URL-safe Base64, hex, digest, forbidden fields, credential grammar,
JSON escaping, invalid or duplicate paths, type/size/count/depth limits,
malformed UTF-8/JSON, links, hard links, special files, mount/race changes,
invalid canary input, and sanitized internal failure.

Any nonzero finding, incomplete sentinel, or nonzero exit fails closed. A pass
does not authorize public export; public artifact design remains M11.

### 13.3 Cross-process canary scan

Plant only synthetic bounded canaries and record fixed zero-match or result
codes across:

- API, ingress, tunnel, worker, broker, backup, and recovery journals;
- metrics and alert labels/annotations;
- protected operator reports;
- NPM static-check output and protected generated configuration;
- backup/recovery status artifacts; and
- M10 evidence artifacts.

Do not retain matching content or private filesystem paths in acceptance
evidence.

Remove all canary inputs and candidate fixtures, then repeat a bounded absence
check over the approved paths. Preserve only the fixed scanner/result fields
and content-free cleanup confirmation.

## 14. Phase 8: Refresh the NPM exposure boundary

### 14.1 Authorization checkpoint

Obtain approval for the exact NPM proxy host/location, external approved and
unapproved source classes, backend counter, protected generated-config capture,
probe matrix, rate bound, and test window. Record baseline counters and current
NPM/service identity. Authorized mutations are limited to temporary counters
and bounded requests; configuration changes are not part of the proof unless
separately approved. Stop on unexpected backend contact, redirect, public
listener, rate-limit impact, or config identity drift, then remove only the
temporary drill instrumentation.

Run the installed NPM drift gate from an external approved and unapproved
vantage. Record fixed results for:

- installed NPM/OpenResty/image identity;
- the sanitized static checker against a protected complete `nginx -T`;
- exact server, location, real-IP, proxy, method, and listener counts;
- an unapproved baseline request;
- `Forwarded`, `X-Forwarded-For`, and `X-Real-IP` spoof attempts;
- zero backend-counter increments for every rejected attempt;
- approved exact HTTPS `/mcp` reaching the uniform unauthenticated response;
- invalid path, query, trailing slash, method, and plaintext HTTP rejection
  without redirect or unintended backend contact;
- absence of a direct public backend path; and
- clean canary scans of the generated config and service output.

Remove temporary counters and protected configuration captures, then repeat
the absence check. External alert delivery is irrelevant to this gate; an
external network vantage is required because local requests cannot prove the
public exposure boundary.

## 15. Phase 9: Final verification and acceptance

### 15.1 Repository gate

Frozen release `73814b6` has already passed the complete repository,
PostgreSQL 17 zero-skip, local recovery, and rule gates. Evidence-only commits
that change only bounded evidence, acceptance, or closeout-authority text do
not create a new candidate and must not be substituted for the installed
revision.

If a later change affects executable behavior, checked-in deployment
configuration, schema, migration, generated artifacts, or dependencies, freeze
that reviewed descendant as the new candidate and run:

```bash
make PNPM='npx --yes pnpm@10.15.0' verify
```

For such a new candidate, run the required PostgreSQL 17 integration gate with
database tests forced and the Debian PostgreSQL 17 binary directory explicitly
selected. No required database or recovery test may skip. Re-run:

- the installed-helper PITR gate;
- local signed-history restoration, then encrypted bundle materialization and
  clean disposable-database restore bound to the exact same head, manifest,
  high-water mark, signer policy, and object bytes;
- `promtool check rules`;
- `promtool test rules`; and
- targeted installed deployment/permission tests.

### 15.2 Cleanup inventory

Before deletion or service-state cleanup, obtain approval for the exact
pre-inventoried paths, mount points, processes, listeners, sessions, counters,
credentials, reports, and overrides created by the drills. Resolve and validate
each target's owner, type, device, ancestry, and provenance against that
inventory. Stop on a symlink, mount change, unexpected owner/type, unresolved
variable/glob, shared production path, or any ambiguity. Cleanup authorization
does not extend to accepted recovery-store or canonical objects.

Inventory and remove:

- temporary recovery credentials and `age` identity staging;
- decrypted databases and only the pre-inventoried drill-owned bundle/WAL
  copies and scratch configuration below disposable recovery roots;
- disposable PostgreSQL instances, sockets, and listeners;
- synthetic content, credentials, canaries, and request files;
- temporary NPM/firewall counters and protected config captures;
- temporary Prometheus storage, listeners, and rule files;
- operator test reports outside the retained protected evidence set; and
- temporary mounts, sessions, and service overrides.

Perform an independent second check. Confirm production recovery objects and
canonical state are unchanged except for explicitly authorized backup,
credential, monitoring, and ledger operations.

Never delete an accepted encrypted base, WAL/history object, restore point,
hold, signed-archive source, or retained encrypted bundle during cleanup.

### 15.3 Acceptance record

Record:

- final source revision and immutable source archive SHA-256;
- installed revision, migration, executable and unit digests;
- database wrapper/capability membership, both tenant-binding results,
  function-grant convergence, direct-access/payload/mutation/cross-tenant
  denial results, and bounded snapshot/report function results;
- fixed results and bounded counts/digests for every gate;
- installed backup/WAL identifiers and recovery window;
- measured RPO/RTO;
- accepted ledger anchor count/head and reconciliation result;
- local monitoring, rule, report, retention-cap, scanner, and NPM results;
- cleanup and second-check results; and
- remaining risk references by ADR or issue identifier only.

Mark Forgejo provider recovery and remote continuation `excluded / not
evaluated`, Backblaze provider evidence `non-blocking / not evaluated`, and
external notification delivery `non-blocking / not evaluated`. Do not mark any
of them passed without independent evidence.

Change the milestone decision to **ACCEPTED** only when every required row in
the narrowed matrix passes at the exact installed candidate revision.

## 16. Gate matrix

| Gate | Planning status | Required closure evidence |
|---|---|---|
| ADR 0034 local archive scope | Passed | Accepted ADR and reconciled acceptance/threat/runbook text |
| ADR 0035 no-prune retention | Architecture passed; installed validation pending | Accepted ADR; installed validation-only result and no deletion |
| ADR 0036 single-NFS recovery topology | Architecture passed; installed validation pending | Accepted sole-mount topology, exact permission-bounded directories, shared-fate claim boundary, and local scratch contract |
| Final repository verification | Passed at frozen release | Frozen candidate `make verify`, PG17 zero-skip gate, and local recovery/rule gates; rerun only for a new runtime candidate |
| Local signed-archive restoration | Passed at frozen release | Exact anchored history/tree verification and clean isolated local restore |
| Encrypted local bundle restoration | Passed at frozen release | Real `age` materialization followed by same-anchor clean database restore, wrong-key/corruption rejection, and cleanup |
| Archive continuation/exporter append | Excluded | No closure evidence required; no continuation or resumed-exporter claim permitted |
| Immutable installed candidate | Passed in Phase 1 | Source checksum, installed revision/migration, unit/executable digests |
| Installed observability/report DB boundary | Passed in Phase 1 | Both wrapper bindings; grant convergence; payload/table/mutation/cross-tenant denials; snapshot and nine bounded report function results |
| Installed service hardening | Phase 1 audit passed; lifecycle drills pending separately | Effective unit, credential, privilege, listener, mount, and disabled-surface audit |
| Installed recovery prerequisites | Pending authorization and provisioning | Exact sole `/mnt/memory` mount and encrypted-store directories, local plaintext scratch roots, public recipient, isolated recovery boundary, and synthetic sealed-content deployment/preflight |
| Installed encrypted base/WAL chain | Pending | Verified current encrypted chain, continuity, custody, timer, capacity, and no-prune results |
| Installed-store PITR | Pending | Production helper A/B-not-C, integrity, RPO/RTO, credential/destruction, and cleanup evidence |
| Non-Forgejo credential lifecycle | Pending | Replacement, next-use rejection, revocation/session, canary, and cleanup results per active class |
| Backup-aware hard forget | Pending | Exact pre-forget correlation binding plus ledger/tombstone/material and stale key-provider/fresh-PITR non-resurrection within the ADR 0034 boundary |
| Production-local monitoring | Partial | Installed scrape/rules, local fault pending/firing/recovery, zero eval errors, reports and byte caps |
| Leakage and cross-process canaries | Repository gates passed; installed captures pending | Exact scanner fields and fixed zero-match/result codes |
| NPM exposure boundary | Static contracts passed; external proof pending | External spoof rejection and zero backend-contact proof |
| Cleanup and final bookkeeping | Pending | Exact teardown inventory, second check, source checksum, migration, final decision |
| Forgejo operations | Excluded | No closure evidence required; no success claim permitted |
| Backblaze provider evidence | Non-blocking | No closure evidence required; no offsite-copy claim permitted |
| External alert delivery | Non-blocking | No closure evidence required; no delivery claim permitted |

## 17. Global stop conditions

Stop the current live phase and preserve content-free diagnostics if any of the
following occurs:

- installed revision, migration, or configuration digest differs from the
  accepted candidate;
- rollback or a clean isolated destination is unavailable;
- a credential value, payload, private coordinate, or raw exception enters a
  log, metric, report, command line, or evidence artifact;
- the routine node can access a recovery private identity;
- WAL, manifest, timeline, archive anchor, signer, or ledger state is missing,
  corrupt, divergent, or ambiguous;
- a stale restored key is readable or reconcile runs after API activation;
- any retention operation attempts deletion;
- a required local alert cannot enter and recover from its expected state, or
  rule evaluation errors are nonzero;
- a leakage canary is found or the scanner returns the incomplete sentinel;
- an unapproved/spoofed NPM request contacts the backend;
- a temporary recovery listener becomes remotely reachable; or
- cleanup cannot prove the absence of decrypted or credential-bearing
  artifacts.

## 18. Content-free evidence contract

Evidence may contain release and migration revisions; bounded object IDs;
SHA-256 digests; target time/LSN; elapsed time and RPO/RTO; counts; fixed result
codes; unit/credential class names; owner/mode/link-count results; and cleanup
confirmation.

Evidence must not contain memory statements, proposal bodies, request or actor
identifiers, credential or authorization values, database URLs, private host
names or network coordinates, key material, decrypted data, raw provider
responses, raw exceptions, complete generated configuration, or unbounded
journal/metric output.

Use the protected content-free evidence template. Commit only the bounded
acceptance summary, not the protected operator evidence store.

## 19. Commit and handoff discipline

- Make small coherent unsigned commits after each completed documentation,
  implementation, or evidence-schema checkpoint.
- Include `Co-Authored-By: Codex <codex@openai.com>` in Codex-created commits.
- Do not push under this plan.
- Preserve unrelated worktree changes and the existing planning inputs.
- Keep secrets, live evidence, private coordinates, and decrypted recovery
  material out of Git.
- Do not combine a failed live gate with an unrelated acceptance update.
- A gate remains `pending` until its exact evidence is reviewed.

## 20. Completion definition

Milestone 10 closeout is complete when:

1. ADRs 0034 through 0036 are accepted and all policy/runbook/acceptance text agrees
   with them.
2. The final immutable candidate is installed, audited, and rollback-safe.
3. A current installed encrypted PostgreSQL/WAL chain restores through the
   production helper within the accepted RPO/RTO.
4. Active non-Forgejo credentials rotate/revoke within their defined bounds.
5. Hard forget dominates stale key-provider and installed-PITR copies within
   the ADR 0034 boundary; no archive/secondary-copy erasure claim is made.
6. Production-local monitoring, reports, byte caps, and alert fault/recovery
   behavior pass without payload leakage.
7. Installed leakage/canary and NPM exposure gates pass.
8. Full final verification passes without a required skip.
9. Drill cleanup and an independent second check pass.
10. The acceptance record names the exact accepted source and installed state,
    and makes no unsupported Forgejo, Backblaze, alert-delivery, physical
    erasure, or public publication claim.
