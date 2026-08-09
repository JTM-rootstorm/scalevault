# Secure MCP Tunnel

The tunnel client runs inside the Memory Node LXC and forwards only to the
dedicated authenticated read-only MCP endpoint at
`http://127.0.0.1:8080/chatgpt/mcp`. It opens outbound HTTPS connections to
OpenAI and requires no public listener, reverse-proxy route, or inbound firewall
rule. It never forwards ChatGPT traffic to the direct Codex endpoint at `/mcp`.

This is a fixed-identity `secure_tunnel` deployment profile. The read-only MCP
route must expose only read and status tools and must authenticate the exact
server-issued tunnel credential. It must not trust a caller-provided transport
header or silently fall back to a `direct_private` identity. Keep the service
disabled until that route, its pinned tenant and installation binding, and its
read-only capability profile have passed acceptance.

## Install

Install a checksum-verified official `tunnel-client` release at
`/usr/local/bin/tunnel-client`. Static request and discovery header files were
added in version `0.0.8`; the unit refuses older or incompatible clients. The
currently probed Memory Node binary is `0.0.10`, whose `run --help` and
`doctor --help` both advertise `--mcp.extra-headers` and
`--mcp.discovery-extra-headers`. Recheck those flags after every client
upgrade.

Create a dedicated service account with no membership in `kivra-memory` or
other service groups, then install the preflight helpers and unit:

```sh
useradd --system --user-group --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin memory-tunnel
install -D -o root -g root -m 0755 \
  deploy/memory-node/tunnel/kivra-memory-tunnel-preflight \
  /usr/local/libexec/kivra-memory-tunnel-preflight
install -D -o root -g root -m 0755 \
  deploy/memory-node/tunnel/kivra-memory-tunnel-mcp-probe \
  /usr/local/libexec/kivra-memory-tunnel-mcp-probe
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/kivra-memory-tunnel.service \
  /etc/systemd/system/kivra-memory-tunnel.service
```

Treat an existing account with a different primary group, supplementary group,
shell, or home as a failed prerequisite. The service has no reason to read the
database, application environment, `/mnt/memory`, or the direct Codex bearer
credential.

Install `/etc/kivra-memory/tunnel.env` as `root:root` mode `0600`. It must
contain exactly one setting and no shell expansion:

```text
CONTROL_PLANE_TUNNEL_ID=tunnel_REPLACE_WITH_32_LOWERCASE_HEX_CHARACTERS
```

Install two distinct root-owned mode-`0600`, single-link secret files:

- `/etc/kivra-memory/tunnel-api-key` contains the restricted OpenAI runtime API
  key used only to poll the tunnel control plane.
- `/etc/kivra-memory/chatgpt-mcp-authorization` contains the complete HTTP
  header value `Bearer svb1.<tenant-uuid7>.<credential-uuid7>.<43-character-base64url-secret>`.

The second value must be issued through the reviewed ScaleVault secure-tunnel
credential workflow. Do not copy a direct Codex token, hand-construct a token,
or grant nomination or mutation scopes. Only the tunnel service reads this
one-time bearer value. The API verifies its persisted credential hash using the
existing protected bearer-token pepper and never receives the bearer value.
The tunnel passes only `Authorization: file:%d/...` in its arguments; the
bearer value is absent from the environment, process arguments, unit, and
repository.

The API profile is enabled with these non-secret settings:

```text
KIVRA_MEMORY_CHATGPT_SECURE_TUNNEL_ENABLED=true
KIVRA_MEMORY_CHATGPT_SECURE_TUNNEL_INSTALLATION_ID=REPLACE_WITH_UUIDV7
```

It also requires the existing `KIVRA_MEMORY_CLIENT_TOKEN_PEPPER_CREDENTIAL` and
`KIVRA_MEMORY_CLIENT_TOKEN_PEPPER_KEY_ID` verifier settings documented in the
Memory Node systemd guide. Startup and readiness must fail closed unless the
pepper, key ID, pinned installation, and distinct persisted `secure_tunnel`
credential row are all valid.

The configuration preflight validates the tunnel ID, client version and
static-header features, credential readability, link count, owner-only mode,
and exact bearer grammar without printing secret values. It accepts the
service-owned mode-`0400` copies created by systemd. A second startup preflight
performs a fixed MCP initialize request against `/chatgpt/mcp`. It supplies
Authorization to curl through configuration on standard input, discards the
response body, and fails startup on a missing or malformed credential or
non-success HTTP status.
The secret never appears in curl's arguments, environment, or output. Both
discovery and forwarded MCP calls then use the same protected Authorization
value. Raw HTTP logging, remote UI access, configuration profiles, ambient API
keys, proxy variables, and ambient MCP header settings are removed from the
service environment.

The unit deliberately passes `--log.file=` with an empty value so version
`0.0.10` writes structured logs to standard output for journald. Do not change
this to `--log.file=stdout`: that literal value is treated as a filesystem path
and fails under `ProtectSystem=strict`.

The installed `tunnel-client` 0.0.10 `doctor` command can report absent OAuth
metadata as a failure even when a non-OAuth MCP server initializes correctly.
Use `doctor` as an operator diagnostic, not as a service startup gate. The
payload-silent authenticated initialize request and tunnel `/readyz` are the
deployment gates for this fixed-header route.

## Activate and verify

The service remains disabled until all of these gates are satisfied:

1. The API owns `/chatgpt/mcp`, authenticates the fixed credential as
   `secure_tunnel`, pins the intended installation, and lists no mutation or
   nomination tools.
2. The Platform runtime key has only Tunnels Read and Use permission and the
   tunnel is associated with the intended Platform organization and ChatGPT
   workspace.
3. The environment and both credential files have the documented owner, mode,
   and content boundary.
4. A wrong, missing, revoked, or caller-overridden Authorization value fails
   discovery and tool calls closed.

Place the non-secret secure-tunnel settings in the protected API environment,
restart the API, and prove that the fixed route accepts the dedicated
credential before starting the tunnel. Never check in a concrete installation
ID:

```sh
# In /etc/kivra-memory/memory-api.env:
KIVRA_MEMORY_CHATGPT_SECURE_TUNNEL_ENABLED=true
KIVRA_MEMORY_CHATGPT_SECURE_TUNNEL_INSTALLATION_ID=REPLACE_WITH_UUIDV7

systemctl restart kivra-memory-api.service
/usr/local/libexec/kivra-memory-tunnel-mcp-probe \
  /usr/bin/curl \
  /etc/kivra-memory/chatgpt-mcp-authorization \
  http://127.0.0.1:8080/chatgpt/mcp
```

Then validate and start the tunnel service:

```sh
systemctl daemon-reload
systemd-analyze verify kivra-memory-tunnel.service
systemctl start kivra-memory-tunnel.service
curl --fail --silent --show-error http://127.0.0.1:8081/healthz
curl --fail --silent --show-error http://127.0.0.1:8081/readyz
```

Inspect `journalctl -u kivra-memory-tunnel.service` only for fixed diagnostic
states. Never enable `--log.http-raw-unsafe`, export a support bundle without
review, or paste request/response data into an incident record. The admin UI
remains loopback-only at `http://127.0.0.1:8081/ui`.

After the local checks, refresh the private developer-mode app and verify that
the discovered tool list contains exactly the approved read/status surface.
Exercise a bounded synthetic read, verify `memory_transport_status` reports the
pinned secure-tunnel installation, and verify mutation tools are absent. Keep
the unit disabled if any check fails.

Use the [secure-tunnel rotation runbook](ROTATION.md) for normal credential
rotation and its required live Authorization-collision and journal-canary
gates. Rotation always recovers forward; it never restores a revoked bearer.

## Disaster-recovery reissue

The signed archive restores the secure-tunnel actor, client, installation, and
binding, but intentionally excludes bearer credential rows and verifiers. Keep
the tunnel and ChatGPT route disabled after a restore. A root operator may fill
that exact credential hole with the `reissue-secure-tunnel` subcommand of
`kivra-memory-credential-admin`, supplying the restored tenant, actor, client,
transport binding, and installation UUIDv7 values plus a new `--secret-output`
path.

The command accepts only an exact active ADR 0019 identity with the closed
single-workspace installation profile, read/status-only scopes, and empty
binding operations. It requires zero credential rows for the selected client
and binding, inserts one new bearer only, and never repairs, deletes, or
recreates identity rows. Existing credentials or any drift are hard failures.
The protected output follows the same exclusive-create and retry rules as
initial issuance. Run the authenticated MCP probe with the new artifact before
reenabling the route or tunnel.

This tunnel is for private developer-mode access and is not a public plugin
endpoint. See the official [Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
and the official [tunnel-client configuration reference](https://github.com/openai/tunnel-client/blob/master/docs/configuration.md).
