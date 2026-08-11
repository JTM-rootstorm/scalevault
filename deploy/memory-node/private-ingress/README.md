# Private Codex ingress

This profile gives owner-controlled Codex devices one private HTTPS `/mcp`
route without changing the canonical loopback API or the outbound ChatGPT
tunnel. Nginx Proxy Manager (NPM) terminates client TLS and applies the LAN/VPN
access list. It then uses a separately verified HTTPS connection to the
dedicated Memory Node listener on port `8443`.

Repository files intentionally contain placeholders only. Keep the external
hostname, listener address, NPM egress address, approved client ranges,
certificate material, and bearer credentials in operator-controlled live
configuration.

## Frozen topology

```text
Codex device on approved LAN/VPN
  -> exact private HTTPS hostname and exact /mcp
  -> NPM edge rejection and LAN-only access list
  -> verified backend HTTPS, exact certificate name, pinned CA
  -> exact private Memory Node address:8443/mcp
  -> kivra-memory-codex-ingress.service
```

The service is a direct-only process. It constructs neither the ChatGPT tool
registry nor health, readiness, metrics, OAuth, documentation, or operator
routes. It has no dependency on `kivra-memory-tunnel.service`; stopping either
access path must not stop the other. The existing canonical API remains on
loopback for the exact `/chatgpt/mcp` tunnel target.

## Prerequisites and stop conditions

Before activation, confirm all of the following:

- The NPM Access List contains only the reviewed LAN/VPN source CIDRs.
- NPM rejects every non-LAN/VPN request before selecting or connecting to the
  ScaleVault upstream. A shared or public edge listener is acceptable only
  when this pre-upstream, content-free rejection ordering is verified.
- No public route, NAT rule, UPnP mapping, or HTTP request can reach the
  backend or elicit an MCP, authentication, operator, or backend response.
- NPM has one stable egress IP. Pin it as exactly `/32` for IPv4 or `/128` for
  IPv6 in both the application environment and the systemd network drop-in.
- The LXC firewall permits port `8443` only from that exact NPM egress IP.
- NPM can validate the backend certificate with a pinned private CA and exact
  backend certificate name/SNI. `proxy_ssl_verify off` is forbidden.
- One independently revocable ADR 0018 bearer identity has been provisioned
  for each Codex host or environment. VPN membership is not authorization.

Stop if any one of these cannot be proven. An Access List applied after
upstream selection, plaintext NPM-to-node HTTP, a broad trusted-proxy subnet,
or a shared device bearer is not this profile.

## Memory Node installation

Create these files locally and never add their completed values to Git:

1. Copy `memory-codex-ingress.env.example` to
   `/etc/kivra-memory/memory-codex-ingress.env`. Replace every placeholder and
   install it as `root:root` mode `0600`. The listener host must be one exact
   private IP literal, never a hostname, wildcard, loopback, link-local, or
   public address. Port `8443` is fixed.
2. Install the existing direct-bearer pepper as
   `/etc/kivra-memory/client-token-pepper`, `root:root` mode `0600`. The unit
   exposes it only at
   `/run/credentials/kivra-memory-codex-ingress.service/client-token-pepper`.
3. Provision a backend certificate whose SAN contains the exact private
   backend TLS name used by NPM. Install its certificate and private key as
   `/etc/kivra-memory/codex-ingress-backend-tls-cert` and
   `/etc/kivra-memory/codex-ingress-backend-tls-key`, both `root:root` mode
   `0600`. The unit exposes them only through its own systemd credential
   directory.
4. Copy `kivra-memory-codex-ingress-network.conf.example` to
   `/etc/systemd/system/kivra-memory-codex-ingress.service.d/10-network-policy.conf`,
   replace its placeholder with the same exact NPM `/32` or `/128`, and keep
   the base unit's fail-closed `IPAddressDeny=any` policy.

Install and verify the unit only after those files exist:

```sh
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/kivra-memory-codex-ingress.service \
  /etc/systemd/system/kivra-memory-codex-ingress.service
systemctl daemon-reload
systemd-analyze verify kivra-memory-codex-ingress.service
```

Do not reuse the canonical API sealed-content drop-in. First inspect the live
canonical API composition: if sealed content is disabled there, leave it
disabled on this process. If it is enabled, confirm the live key-provider root,
group ownership, digest-binding recovery material, and canonical create/read/
hard-forget gate. The shared provider's multi-process atomicity test must also
pass with canonical and ingress processes active before ingress activation.

Only after those gates pass, install the ingress-specific drop-in:

```sh
install -D -o root -g root -m 0644 \
  deploy/memory-node/systemd/sealed-content/kivra-memory-codex-ingress.service.d/20-sealed-content.conf \
  /etc/systemd/system/kivra-memory-codex-ingress.service.d/20-sealed-content.conf
systemctl daemon-reload
systemd-analyze verify kivra-memory-codex-ingress.service
```

It loads the same local digest-binding source through the ingress service's
own systemd credential namespace, sets the exact sealed provider root, and
retains the canonical key-directory controls. Do not put sealed settings or
credential paths in `memory-codex-ingress.env`.

## NPM policy

Create one Proxy Host with the exact hostname and certificate. A shared edge is
permitted, but the LAN-only/VPN-only NPM Access List must reject other sources
before upstream selection. Disable Force SSL redirects: plaintext HTTP must
receive the same fixed content-free rejection and must never be proxied. Route
only exact `/mcp`; every other path must return a fixed non-redirecting
rejection.

Adapt `npm-location.conf.example` for the installed NPM version. Its important
properties are contractual:

- upstream scheme is `https`, destination is an exact private IP at port
  `8443` with no DNS resolution, backend SNI and certificate name are separate
  exact pins, and verification uses the pinned CA;
- `proxy_pass_request_headers off` removes every caller-supplied `Forwarded`,
  `Via`, `X-Real-IP`, and `X-Forwarded-*` field; only the explicit MCP header
  allowlist is reconstructed, and the application independently rejects any
  forwarding metadata that survives;
- the external `Host` is normalized to the one configured hostname and a
  supplied `Origin` is preserved for the application's exact validation;
- the 1 MiB request buffer matches the body cap so accepted MCP bodies remain
  in memory and are never spooled to a temporary file, while response buffering
  and gzip stay off for SSE;
- `proxy_next_upstream off` forbids retry or failover, especially for mutation
  POSTs, and `proxy_redirect off` never rewrites an upstream redirect;
- connect, request-body, upstream-send, response-idle, and client-send times are
  explicitly bounded; the application independently enforces a hard 30-second
  POST/DELETE lifetime and a hard five-minute GET/SSE lifetime, after which the
  client reconnects; and
- access logging, caching, and body capture are disabled. Do not enable debug
  logging or any log format containing Authorization, request bodies, MCP
  payloads, query strings, or response bodies.

Inspect NPM's generated configuration after every creation, edit, or upgrade.
If NPM cannot preserve the exact location, private listener, strict header
reconstruction, no-retry behavior, and verified backend TLS, do not activate
the Proxy Host.

## Activation and live acceptance

Keep the service disabled until the full live boundary is ready. Then enable it
without changing or restarting the canonical API or tunnel:

```sh
systemctl enable --now kivra-memory-codex-ingress.service
systemctl status --no-pager kivra-memory-codex-ingress.service
ss -ltnp
```

Record sanitized evidence for all of these checks:

1. `ss` shows the canonical API only on loopback and the Codex ingress only on
   the exact private address at `8443`; neither has a wildcard listener.
2. The LXC firewall and systemd policy allow `8443` only from the exact NPM
   `/32` or `/128`. Direct attempts from another LAN/VPN host fail.
3. NPM's generated configuration has the exact host and `/mcp` location,
   pre-upstream LAN/VPN Access List rejection, strict header reconstruction,
   exact private backend IP, pinned backend CA/SNI, no upstream retry, no
   redirect, and bounded timeouts.
4. Correct TLS validation succeeds on both client and backend hops. Wrong CA,
   wrong SNI/hostname, plaintext, wrong Host, wrong Origin, query strings,
   trailing slashes, forwarding headers, and every non-`/mcp` path fail without
   redirecting.
5. A valid per-device bearer can initialize, read, and mutate. No bearer and a
   revoked bearer fail. Revoking one device blocks its next request without
   affecting another device or ChatGPT.
6. A GET/SSE connection ends at the reviewed lifetime and reconnects normally.
   A deliberately failed mutation is never retried.
7. A canary scan of NPM and service logs finds no Authorization value, MCP body,
   memory payload, query string, or response body.
8. Stopping the tunnel does not affect private Codex access, and stopping the
   private ingress does not affect the tunnel.
9. From a non-VPN external network, every candidate public IP either has no
   route or returns the same fixed content-free pre-upstream rejection for HTTP
   and HTTPS requests using the configured hostname as explicit SNI and Host.
   An independent backend connection or firewall counter must remain at zero
   throughout those probes. Also inspect edge firewall, NAT, UPnP, NPM
   container port publication, and wildcard Proxy Hosts. Private DNS absence
   alone is not proof.

Repository tests cannot establish firewall, NPM, DNS, certificate, NAT, or
internet reachability state. Keep a dated, sanitized live acceptance record;
external coordinates remain live configuration rather than repository data.
