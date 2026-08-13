# Credential lifecycle

This runbook covers every active Milestone 10 ScaleVault credential.
It never authorizes a live provider change. Provider revocation, service
activation, and recovery reissue require a separate operator checkpoint.
The normative lifecycle and revocation semantics are frozen by
[ADR 0030](../adr/0030-credential-lifecycle-and-revocation.md).

Do not place credentials, database URLs, private coordinates, response bodies,
or verifier material in tickets, evidence, command arguments, logs, or this
repository. Record only credential class, public identifier where defined,
timestamps, fixed result codes, and whether the live step was passed, failed,
or not applicable.

## Lifecycle matrix

| Credential | Owner and system of record | Rotation and revocation bound | Recovery posture |
|---|---|---|---|
| Direct Codex bearer | installation owner; PostgreSQL verifier row | atomic replacement; the old bearer fails at the next database-backed request after the revoke commit | reissue after rollback or suspected compromise |
| ScaleVault tunnel bearer | installation owner; PostgreSQL verifier plus protected file | crash-safe forward rotation; database revoke blocks the next request, then fixed-path install and restart replace the static file | reissue only after restored identity review |
| Bearer HMAC pepper | host operator; systemd credential source | maintenance-gap cutover requiring all bearer credentials to be reissued; one runtime key is accepted | restore separately or reissue every bearer; never recover from database or archive |
| OpenAI tunnel credential and association | provider owner; provider plus systemd credential | stop, revoke association/key, stage, preflight, start; the measured provider result is the bound | explicitly reassociate; never infer recovery from a local file |
| GitHub connected app/install | provider owner; GitHub | provider-managed revocation; no live claim while ingress is dormant | explicitly reauthorize if enabled |
| GitHub poll token | ingress operator; GitHub plus systemd credential | stop poller, replace least-privilege token, start; bound includes one reviewed in-flight poll | reissue, do not restore from database or archive |
| GitHub local installation | ingress operator; PostgreSQL | monotonic local revoke; no processing after the selected revocation boundary | review after rollback before any poller activation |
| Archive public signer trust | archive trust owner; external trust anchor | verify the accepted signer policy, transitions, and compromise cutoffs when applicable; no private-key operation is authorized by M10 | never recover trust from the archive it verifies |
| PostgreSQL service password | database operator; PostgreSQL plus per-service systemd credential | replace one role, restart only its consumers, terminate old sessions, verify old login fails | reissue before service activation |
| Backup recipient | recovery custodian; backup manifest and external custody | new objects use the new recipient; retained objects remain decryptable by their recorded recipient | private identity stays separate from backup objects |
| Sealed digest binder | key custodian; systemd credential | no ordinary rotation; replacement requires a reviewed migration | restore separately and verify identity |
| Per-memory DEK | key custodian; external key provider | no ordinary M10 rotation; destruction-ledger tombstones dominate every restore | never restore a DEK whose durable destruction entry exists |

## Common safety gate

Before any change:

1. Identify the exact credential class, consumer units, public identifier, role,
   and recovery dependency. Stop if ownership or system of record is unknown.
2. Confirm an independent recovery/admin session and the prior immutable
   release are available. Do not rely on the credential being changed.
3. Stop affected ingress or worker services when provider-side work can race an
   in-flight request. Leave unrelated direct and tunnel paths running.
4. Stage replacement material as a root-controlled mode-`0600` file. Service
   units load secrets through `LoadCredential`; non-secret identifiers remain
   in environment files.
5. Run `systemd-analyze verify` on the installed candidate and validate the
   secret source owner, mode, link count, and bounded size without printing it.
6. After cutover, test both halves: the replacement performs only its intended
   operation and the old credential fails. Scan bounded logs for a synthetic
   canary, never the real value.

Application credential readers require absolute paths, reject `..`, symlinked
path components, hard links, wrong ownership or mode, empty or oversized files,
and text control characters. Reads and final metadata validation use the same
open descriptor so pathname substitution cannot change consumed bytes.

## Direct Codex bearer

Use the existing `kivra-memory-credential-admin` commands documented in
[`deploy/memory-node/systemd/README.md`](../../deploy/memory-node/systemd/README.md).
Rotation has no overlap for one binding: the transaction revokes the old row
and creates the replacement atomically.

1. Create a new one-time output path under a root-only temporary directory.
2. Run `rotate` with the tenant and old credential UUID. Never use a terminal-
   visible secret output method.
3. Import the output directly into the client OS credential store and remove
   the temporary file.
4. Prove the old bearer fails on its next request, the replacement succeeds,
   and another client is unaffected.

If output publication fails after the database commit, the old bearer remains
revoked. Use `list-metadata` to identify the replacement, then revoke or rotate
that replacement into a fresh unused output path. Never reactivate the old row.

Pepper replacement remains a maintenance-gap procedure. Stop every bearer-
authenticated API/ingress process, install the replacement systemd credential,
reissue clients under the new key ID, restart, verify replacements, and revoke
superseded rows. Do not introduce dual-pepper fallback without a reviewed
architecture change.

## ScaleVault tunnel bearer and OpenAI association

Follow [`deploy/memory-node/tunnel/ROTATION.md`](../../deploy/memory-node/tunnel/ROTATION.md)
for the database bearer and fixed authorization file. A failure after database
commit always moves forward; never restore the revoked old bearer.

For provider credential or workspace/app association replacement:

1. Stop `kivra-memory-tunnel.service`; verify direct private access is
   unaffected.
2. At the provider, revoke the old credential or association. Record only its
   public identifier and provider timestamp.
3. Stage the replacement at the existing systemd credential source and run
   `kivra-memory-tunnel-preflight` plus the authenticated local MCP probe.
4. Start the tunnel, verify service readiness and an account-side memory read,
   then scan bounded JSON logs for canaries.
5. Measure and record when the old provider credential stopped working. Do not
   convert a provider observation into a stronger guarantee than observed.

## GitHub ingress

The normal private deployment keeps `kivra-memory-github-ingress.service`
disabled and its token absent. Verify both conditions. Record provider
revocation as **not applicable**, not passed.

If separately authorized and active, distinguish the connected app/install,
poll token, webhook secret (normally absent), and PostgreSQL installation row.
Stop the poller before provider revocation, rotate only a repository-read token,
then prove no provider-head, quarantine, receipt, or canonical progress occurs
under the revoked local installation. HTTP `401`/`403` and rate limits must
enter bounded backoff; response bodies are untrusted and must not be logged.

## Deferred Forgejo credentials (not M10)

Forgejo provider credentials, deploy-key and host-key exercises, provider API
operations, and exporter activation are excluded from M10. Verify that their
consumer is disabled and do not provision, rotate, revoke, or test them for M10
acceptance. The following guidance is retained for future separately authorized
Forgejo operation; its result cannot close an M10 gate.

### Forgejo deploy key, host key, and archive signer

Deploy-key rotation is independent from signing-key transition:

1. Add a repository-scoped replacement deploy key without changing signer
   trust. Verify fetch plus the one intended exporter push against unchanged
   history; never force-push.
2. Revoke the old deploy key and prove it fails. Divergence is preserve-and-
   investigate; use [`archive-divergence.md`](archive-divergence.md).
3. Treat a Forgejo host-key change as an incident until independently verified.
   Update the pinned known-hosts file only from a trusted administrative path.
4. Rotate a signing key only under the accepted signer-transition policy.
   Verify historical commits under their recorded epoch and reject new commits
   from a compromised old signer. Never silently delete historical trust.

M10 verifies only public signer trust for local signed-history and encrypted-
bundle recovery. It does not provision, invoke, rotate, or revoke an archive
signing private key. Live signer work requires separate authorization and is
required only when the accepted policy declares a transition or compromise.

## PostgreSQL service passwords

Rotate one role at a time. Its database URL is a per-unit `LoadCredential`
source (`database-url`, or the two named GitHub database credentials), not an
environment value.

1. Stop only the consumer units for the role.
2. Change the PostgreSQL password over a protected local admin session.
3. Atomically replace the root-owned credential source, reload systemd, and
   start the consumers.
4. Verify readiness and the exact role privileges, terminate sessions
   authenticated before the change, and prove a fresh login with the old
   password fails.

Never put the URL in `systemctl show`, process arguments, an evidence file, or
shell history. A PostgreSQL rollback does not roll back external credential
sources; review and reissue them before services are re-enabled.

## Backup and sealed-key material

Recipient transition applies the new recipient only to new encrypted objects.
Inventory every retained chain by recipient before retiring a private identity;
M10 has zero authority to prune any recovery chain. Restore drills use isolated
destinations and separately supplied private identities.

The sealed digest binder and per-memory DEKs are separate. Do not rotate the
binder as routine credential hygiene. During key recovery, consult the durable
destruction ledger before publishing any material: a destruction tombstone
always wins over a stale key backup. See the backup and hard-forget recovery
runbooks for the complete gate.

## Evidence and compromise response

For every drill, record the credential class, public identifier, owner,
consumer units, start/finish time, old-credential rejection result, replacement
operation result, rollback disposition, recovery posture, and remaining risk.
Never record secret values or verifier bytes.

On suspected compromise, stop the smallest affected ingress/writer boundary,
revoke at the system of record, preserve payload-safe provider and service
metadata, rotate downstream credentials only when exposure is plausible, and
run the old-fails/new-passes gate. If revocation cannot be proven, keep the
affected service disabled.
