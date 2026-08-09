# Secure-tunnel credential rotation

This runbook rotates the fixed ChatGPT secure-tunnel bearer without changing
its actor, client, installation, transport binding, scopes, or read capability.
It is the normal rotation procedure, not the archive-restoration reissue path.

Run it with Bash as root from a trusted local console with shell tracing
disabled. Record the existing tenant UUIDv7 and active credential UUIDv7 from
`kivra-memory-credential-admin list-metadata`. Never print either bearer, use
`--secret-stdout`, place a bearer in an environment variable, or copy it into an
incident record.

## Normal cutover

Choose a new request-local UUIDv7 for `rotation_id`. The staging directory is
on the same filesystem as the fixed credential so the final replacement is one
atomic rename.

```sh
set +x
set -euo pipefail
umask 077
tenant_id=REPLACE_WITH_TENANT_UUIDV7
old_credential_id=REPLACE_WITH_ACTIVE_CREDENTIAL_UUIDV7
rotation_id=REPLACE_WITH_NEW_REQUEST_UUIDV7
rotation_started_at=$(date --iso-8601=seconds)
staging_dir=/etc/kivra-memory/tunnel-rotation
fixed_authorization=/etc/kivra-memory/chatgpt-mcp-authorization
old_proof="$staging_dir/old-$rotation_id.authorization"
new_artifact="$staging_dir/new-$rotation_id.authorization"

install -d -o root -g root -m 0700 "$staging_dir"
test ! -e "$old_proof"
test ! -e "$new_artifact"
/usr/local/libexec/kivra-memory-tunnel-mcp-probe \
  /usr/bin/curl "$fixed_authorization" \
  http://127.0.0.1:8080/chatgpt/mcp
install -o root -g root -m 0600 "$fixed_authorization" "$old_proof"

kivra-memory-credential-admin rotate-secure-tunnel \
  --tenant-id "$tenant_id" \
  --credential-id "$old_credential_id" \
  --secret-output "$new_artifact"
```

The command creates `new_artifact` exclusively before it atomically revokes the
old database credential and inserts its replacement. It prints only safe
metadata. After it succeeds, prove the replacement works and the old verifier
is already revoked before changing the fixed path:

```sh
/usr/local/libexec/kivra-memory-tunnel-mcp-probe \
  /usr/bin/curl "$new_artifact" \
  http://127.0.0.1:8080/chatgpt/mcp
if /usr/local/libexec/kivra-memory-tunnel-mcp-probe \
  /usr/bin/curl "$old_proof" \
  http://127.0.0.1:8080/chatgpt/mcp; then
  echo 'rotation failed: revoked credential was accepted' >&2
  exit 1
fi
```

Atomically replace the fixed artifact, make the rename durable, and restart
only the tunnel. Do not restart by restoring the old artifact.

```sh
mv -T -- "$new_artifact" "$fixed_authorization"
sync -f /etc/kivra-memory
systemctl restart kivra-memory-tunnel.service
/usr/local/libexec/kivra-memory-tunnel-mcp-probe \
  /usr/bin/curl "$fixed_authorization" \
  http://127.0.0.1:8080/chatgpt/mcp
if /usr/local/libexec/kivra-memory-tunnel-mcp-probe \
  /usr/bin/curl "$old_proof" \
  http://127.0.0.1:8080/chatgpt/mcp; then
  echo 'rotation failed: revoked credential was accepted after restart' >&2
  exit 1
fi
curl --fail --silent --show-error http://127.0.0.1:8081/healthz
curl --fail --silent --show-error http://127.0.0.1:8081/readyz
kivra-memory-credential-admin list-metadata --tenant-id "$tenant_id"
```

Confirm that metadata shows the old credential revoked and exactly one active
replacement for the pinned secure-tunnel client. After all activation gates
below pass, remove only the named revoked proof artifact and the empty staging
directory:

```sh
rm -f -- "$old_proof"
rmdir --ignore-fail-on-non-empty -- "$staging_dir"
```

## Crash recovery

First stop repeated tunnel retries, retain every uniquely named staged
artifact, and inspect safe credential metadata. Do not delete an artifact until
the database state is known.

```sh
systemctl stop kivra-memory-tunnel.service
kivra-memory-credential-admin list-metadata --tenant-id "$tenant_id"
```

### Before database rotation

If the old credential is still active and there is no replacement, no database
cutover occurred. If `new_artifact` exists, rerun the exact
`rotate-secure-tunnel` command with the same old credential UUID and the same
artifact path. The command reloads that protected artifact and completes the
same rotation. If the artifact does not exist, the exact command may create it.
Do not install an artifact until the command succeeds and its direct
authenticated probe succeeds.

### After database commit, before fixed-path install

The old fixed artifact is revoked and must not be used to restart the tunnel.
Keep the service stopped. Probe `new_artifact`, atomically rename it to
`fixed_authorization`, run `sync -f /etc/kivra-memory`, and continue with the
normal restart and positive/negative proofs.

If the committed replacement's artifact was lost, it cannot be recovered from
PostgreSQL. Use `list-metadata` to identify the one active replacement
credential, then run `rotate-secure-tunnel` on that replacement credential UUID
with another unique output path. This is a second forward rotation. Install
only its new artifact. Do not use `reissue-secure-tunnel`, which is restricted
to an archive-restored identity with no credential row.

### After fixed-path install, before restart

The fixed path contains the active replacement while the existing tunnel
process may still hold the revoked value in memory. Keep or stop that process,
probe the fixed artifact directly, and restart the tunnel. Do not move
`old_proof` back to the fixed path. Repeat the post-restart positive and
negative proofs before declaring recovery complete.

### Failed restart

Leave the new fixed artifact in place and keep the tunnel stopped. Inspect only
sanitized service status and journal diagnostics, then repair the binary,
control-plane credential, API readiness, route configuration, workspace
association, or network dependency that failed. A successful direct probe of
the fixed artifact proves the ScaleVault verifier side independently of the
OpenAI control-plane connection.

If metadata and the fixed artifact cannot be reconciled, rotate the currently
active replacement forward to another unique artifact and repeat the cutover.
Never silently re-enable the revoked old credential, restore `old_proof`, or
edit a credential row by hand.

## Required live gates

Rotation is incomplete until both of these tests run through the actual OpenAI
tunnel, not a direct loopback client.

1. **Authorization collision:** send one bounded tunneled MCP request with no
   connector-supplied Authorization header and prove the fixed static header
   succeeds. Then send the same request with a deliberately invalid,
   connector-forwarded Authorization header. Because the official tunnel
   client applies connector-forwarded headers last, the conflicting value must
   override the static header and the Memory Node must reject the request. Any
   successful read in the collision case is a release blocker. Record only the
   HTTP/MCP outcome and opaque request ID, never either Authorization value.
   See the official [tunnel-client configuration reference](https://github.com/openai/tunnel-client/blob/master/docs/configuration.md#connector-and-mcp-routing)
   for the header precedence contract.
2. **Journal canary:** through ChatGPT, invoke a bounded `memory_search` for a
   unique non-secret marker such as `tunnel-log-canary-<UUIDv7>` and expect no
   matches. Scan both service journals from `rotation_started_at`; the marker,
   bearer grammar, and Authorization header name must all be absent.

```sh
canary=tunnel-log-canary-REPLACE_WITH_UUIDV7
set +e
journalctl \
  --since "$rotation_started_at" \
  --unit kivra-memory-api.service \
  --unit kivra-memory-tunnel.service \
  --output cat \
  --no-pager \
  | grep -E -q "$canary|Bearer svb1\.|Authorization:"
scan_status=("${PIPESTATUS[@]}")
set -e
if [ "${scan_status[1]}" -eq 0 ]; then
  echo 'rotation failed: tunnel secret or canary appeared in the journal' >&2
  exit 1
elif [ "${scan_status[0]}" -ne 0 ] || [ "${scan_status[1]}" -ne 1 ]; then
  echo 'rotation failed: journal canary scan was unavailable' >&2
  exit 1
fi
```

Finally refresh the private ChatGPT app's frozen tool snapshot, confirm the
exact read/status-only tool list, perform one bounded synthetic read, and
confirm `memory_transport_status` still reports the pinned secure-tunnel
installation.
