# ADR 0030: Credential lifecycle and revocation

- Status: Accepted
- Date: 2026-08-12
- Supersedes: None
- Extends: ADR 0018, ADR 0019, ADR 0022, and ADR 0029

## Context

ScaleVault has strong request-scoped bearer checks, but its active topology also
depends on provider control-plane identities, Forgejo transport, archive
signing, PostgreSQL roles, backup recipients, and sealed-content secrets. Their
rotation and recovery semantics differ. Treating a database restore, service
restart, or provider response as universally sufficient would leave rollback
and revocation gaps.

GitHub proposal ingress has a provider installation, a poll credential, and a
local installation identity. Local revocation must define whether work may
continue to create non-canonical ingress state after canonical mutation is
disabled.

## Decision

### Lifecycle matrix

| Credential or identity | System of record | Rotation mode | Revocation bound | Recovery posture |
|---|---|---|---|---|
| Direct Codex bearer | PostgreSQL | Atomic replacement with a maintenance gap unless a later ADR accepts overlap | No new request after the revoke transaction commits and the required in-request recheck completes | Reissue after rollback or compromise; restored rows do not activate ingress |
| ScaleVault tunnel bearer | PostgreSQL plus protected credential file | Existing crash-safe forward rotation | No new authenticated request after revoke commit; restart must not retain a stale static file | Reissue only into the exact verified restored tunnel identity |
| Bearer HMAC pepper | Root-controlled system credential | Full client reissue and coordinated cutover; dual-key acceptance requires a later reviewed design | Old verifiers unusable after cutover and service restart | Never restore from database or archive; supply and verify separately |
| OpenAI tunnel key and association | Provider plus protected system credential | Stop tunnel, revoke provider identity/association, stage, preflight, reassociate, restart | Provider-observed bound measured in the drill | Reassociate explicitly; never infer from restored local state |
| GitHub connected app or installation | Provider | Provider-managed replacement/revocation | Provider-observed bound measured in the drill | Reauthorize explicitly only when ingress is enabled |
| GitHub poll token | Provider plus protected system credential | Stop worker, replace least-privilege token, preflight, restart | One configured poll interval plus bounded in-flight rechecks, subject to the stronger local-installation rule below | Reissue; never recover from database/archive |
| GitHub local installation | PostgreSQL | Monotonic local revoke | No post-revocation processing after commit and required recheck | Review against rollback before any reauthorization |
| Forgejo deploy key | Forgejo plus protected system credential | Add replacement, verify repository-scoped operation, then revoke old key | No successful push after provider revocation; terminate stale sessions in the drill | Reissue repository-scoped; never obtain from archive |
| Archive signing key | External signer custody plus ADR 0029 signer epoch | Planned dual-signed epoch transition or independently authorized compromise transition | Old key valid only for its exact anchored epoch and compromise cutoff | Never recover from archive or database |
| PostgreSQL service password | PostgreSQL plus one protected credential per role/service | Replace one role, restart its services, terminate old sessions, verify, then continue | Old password and old sessions unusable after the runbook completes | Reissue before activation; restored password references do not authorize service start |
| Backup recipient | Authenticated backup manifest plus external custody | Versioned recipient transition; new objects use the new recipient, retained objects remain bound to the old | Old recipient remains relevant while an object encrypted to it is retained | Private identity held separately from backup objects and routine node |
| Sealed digest binder | Root-controlled system credential | Exact-secret recovery or explicit reviewed migration only | Missing or mismatched binder fails sealed idempotency and correlation closed | Restore separately and verify identity before sealed operations |
| Per-memory DEK | External key provider plus ADR 0028 destruction ledger | No ordinary M10 rotation | Destruction-ledger fact dominates every provider backup and read | Restore provider only after independent ledger validation and reconciliation |

Operator-specific provider identities, recipients, paths, rotation windows, and
acceptable maintenance times are required activation inputs and are not fixed
by this ADR.

### Common rotation and compromise rules

Every active credential has one named operational owner, least-privilege scope,
system of record, protected delivery path, maximum age or explicit non-expiring
justification, rotation procedure, revocation test, compromise procedure, and
recovery posture. A dormant integration proves both its service and credential
absent; an unavailable provider drill is recorded as not applicable, not
passed.

Rotation is forward-only and crash safe. Replacement is staged without placing
secret bytes in arguments, environment dumps, logs, metrics, Git, reports, or
acceptance artifacts. The old credential is revoked only after the replacement
passes its narrow preflight, except during compromise, when containment takes
priority. Failure after revocation recovers forward with a fresh credential; it
does not re-enable the compromised one.

Provider 401/403, rate limits, and outages use bounded backoff and fixed error
codes and never log response bodies. Provider revocation bounds are measured
from the actual provider and recorded content-free. A local database flag does
not claim that a provider token has been revoked, and provider revocation does
not silently repair stale local authorization.

Restores keep all externally reachable services, workers, pollers, tunnel
processes, and exporters disabled. Credentials whose authority could have
rolled back are reissued, rotated, reassociated, or explicitly reviewed before
activation. Secrets excluded by ADR 0015 are never reconstructed from archive
content. Credential files must be absolute, regular, single-link, no-follow,
correctly owned and mode-restricted, bounded in size, and loaded through a
service-specific protected credential boundary.

### GitHub local-revocation semantics

Once local installation revocation commits, ScaleVault performs no later
processing for that installation: no provider-head discovery, fetch, parsing,
validation, quarantine, selection, decision, receipt, checkpoint update, or
canonical event. Work already in flight rechecks the local installation
immediately before every durable write and aborts with a fixed content-free
outcome if revocation won the race. Restart and retry preserve the prohibition.

Provider polling may perform only the minimum request needed to observe the
revocation condition already in flight; it must not persist newly discovered
state. Reauthorization creates or explicitly reactivates a reviewed binding
under a separate operator action. Database rollback to a pre-revocation row is
not sufficient and requires comparison with protected operational revocation
evidence before the worker can run.

## Consequences

- Rotation procedures differ by trust domain but share one fail-closed recovery
  and evidence discipline.
- Direct bearer and pepper cutovers may require a maintenance gap; accepting
  simultaneous old and new secrets needs a separate design.
- GitHub local revocation stops all post-revocation ingress state, not merely
  canonical memory events.
- Archive signing trust follows epochs and cutoffs, while deploy and host keys
  remain independent transport credentials.
- Restoring a database or credential filename never automatically restores
  external authority or service exposure.
