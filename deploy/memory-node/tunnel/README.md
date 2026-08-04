# Secure MCP Tunnel

The tunnel client runs inside the Memory Node LXC and forwards only to the
loopback MCP endpoint at `http://127.0.0.1:8080/mcp`. It opens an outbound HTTPS
connection to OpenAI; it does not require a public listener, reverse-proxy
route, or inbound firewall rule.

Install the checksum-verified official `tunnel-client` binary at
`/usr/local/bin/tunnel-client`, then install
`kivra-memory-tunnel.service`. Create the service account:

```sh
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin --gid kivra-memory memory-tunnel
```

Place only the tunnel identifier in `/etc/kivra-memory/tunnel.env`:

```text
CONTROL_PLANE_TUNNEL_ID=tunnel_REPLACE_WITH_32_LOWERCASE_HEX_CHARACTERS
```

Place the restricted runtime API key in
`/etc/kivra-memory/tunnel-api-key`, owned by root with mode `0600`. The systemd
unit exposes it to the service as a transient credential; do not store the key
in this repository, the environment file, or on the NAS. The daemon uses direct
flags and the system journal, so it does not need mutable durable state. The NAS
ACL must not be trusted as a secret boundary while broad modify access is
enabled.

Keep the service disabled at boot unless continuous private access is intended.
After associating the tunnel with the intended Platform organization and
ChatGPT workspace, validate the credential and tunnel with:

```sh
systemctl start kivra-memory-tunnel.service
curl --fail --silent --show-error http://127.0.0.1:8081/healthz
curl --fail --silent --show-error http://127.0.0.1:8081/readyz
```

The admin UI remains loopback-only at `http://127.0.0.1:8081/ui`. This tunnel
is for private developer-mode access and is not a public plugin endpoint.

The systemd unit waits for the loopback Memory API readiness endpoint before
starting `tunnel-client`. This prevents the client's startup-only MCP probe from
capturing a transient database or migration failure when both units start
together.
