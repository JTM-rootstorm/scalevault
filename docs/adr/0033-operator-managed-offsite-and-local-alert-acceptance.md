# ADR 0033: Operator-managed offsite and local alert acceptance

- Status: Accepted
- Date: 2026-08-12
- Supersedes: None
- Amends: ADR 0027, ADR 0029, and ADR 0031

## Context

ADRs 0027 and 0029 require encrypted recovery objects suitable for an
independent offsite failure domain. ADR 0031 requires tested alert rules and
identifies an external receiver as an operator activation input. Neither
ScaleVault's semantic authority nor the correctness of its recovery and alert
logic depends on ScaleVault owning a particular storage-provider client or
notification service.

The operator has selected Backblaze for offsite custody and has selected local
alert evaluation without making external notification delivery a Milestone 10
acceptance dependency. Repository or installed-system acceptance must not
invent Backblaze buckets, accounts, endpoints, credentials, retention settings,
or an alert receiver merely to turn those operator-managed boundaries into
application features.

## Decision

### Operator-managed Backblaze boundary

ScaleVault Milestone 10 produces, atomically publishes to its configured local
recovery store, and locally verifies the `age`-encrypted PostgreSQL base-backup,
WAL, recovery-manifest, and full-history Git-bundle objects defined by ADRs 0027
and 0029. A recovery drill must use independently supplied private recovery
material to authenticate and decrypt those exact object formats and must prove
PITR or signed-archive restoration as applicable. These format, encryption,
integrity, exclusion, and restore gates remain mandatory.

Transfer to and lifecycle management within Backblaze are operator-managed.
ScaleVault does not receive Backblaze credentials, implement a Backblaze API
client, or treat provider listings, metadata, checksums, retention, or deletion
policy as semantic or recovery authority. The operator remains responsible for
placing encrypted objects and their content-free sidecars into a Backblaze
failure domain independent of the canonical NAS and primary Forgejo service,
monitoring that copy, and periodically retrieving exact ciphertext for an
offsite drill.

Backblaze configuration, transfer, freshness, and retrieval evidence are not
Milestone 10 blockers. Their absence means acceptance may claim only that
ScaleVault produced and locally restored offsite-suitable encrypted recovery
objects. It must not claim that an independent Backblaze copy exists, is
current, satisfies provider retention, or has been restored. A later operator
record may add those claims without changing canonical ScaleVault state.

### Local alert-evaluation boundary

Milestone 10 requires checked-in alert rules to pass syntax and behavioral
tests and requires the installed private Prometheus instance to evaluate those
rules locally. Fault injection must prove each required condition enters and
leaves its expected pending/firing state, rule-evaluation errors remain zero,
and alert labels and annotations stay within the content-free contract. Local
scrape freshness, rule health, retention limits, and protected operator
inspection remain required.

No external notification receiver or delivery integration is required for
Milestone 10. Missing receiver configuration and absent delivery evidence are
not failures when local evaluation is healthy. ScaleVault does not invent an
email, webhook, paging, or hosted-alert destination. If the operator later
enables a receiver, its credentials, destination, disclosure policy, delivery
tests, and retention are a separate operator-managed activation boundary.
Delivery failure must remain locally observable, but it does not invalidate a
correct local rule evaluation or stop the Memory Node.

This amendment does not remove external blackbox probing required to establish
the private-ingress exposure boundary. It distinguishes where a security probe
runs from where an alert notification is delivered.

## Consequences

- M10 verifies recovery-object correctness and restorability without embedding
  provider credentials or a provider-specific storage client in ScaleVault.
- Backblaze supplies the chosen offsite administrative boundary, but provider
  transfer and recovery claims remain explicitly unverified until the operator
  records them.
- Alert-rule correctness is proved locally and remains privacy bounded; external
  notification delivery may be activated later without reopening M10.
- No recovery, encryption, archive-signature, local-retention, rule-evaluation,
  or public-exposure correctness gate is weakened by this amendment.
