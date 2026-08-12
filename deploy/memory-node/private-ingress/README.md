# Private Codex ingress

This profile gives owner-controlled Codex devices one private HTTPS `/mcp`
route without changing the canonical loopback API or the outbound ChatGPT
tunnel. Nginx Proxy Manager (NPM) terminates client TLS and applies the LAN/VPN
access list. It then uses private HTTP to the dedicated Memory Node listener on
port `8443`; the exact NPM peer pin and LXC firewall isolate that backend hop.

Repository files intentionally contain placeholders only. Keep the external
hostname, listener address, NPM egress address, approved client ranges,
and bearer credentials in operator-controlled live configuration.

## Frozen topology

```text
Codex device on approved LAN/VPN
  -> exact private HTTPS hostname and exact /mcp
  -> NPM edge rejection and LAN-only access list
  -> private HTTP from one exact NPM egress address
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
- Except for ADR 0026's static ACME renewal prefix, NPM rejects every
  non-LAN/VPN ScaleVault application request before selecting or connecting to
  the upstream. A shared or public edge listener is acceptable only when this
  pre-upstream, content-free rejection ordering is verified.
- No public route, NAT rule, UPnP mapping, or HTTP request can reach the
  backend or elicit an MCP, authentication, operator, or backend response.
- NPM has one stable egress IP. Pin it as exactly `/32` for IPv4 or `/128` for
  IPv6 in both the application environment and the systemd network drop-in.
- The LXC firewall permits port `8443` only from that exact NPM egress IP.
- One independently revocable ADR 0018 bearer identity has been provisioned
  for each Codex host or environment. VPN membership is not authorization.

Stop if any one of these cannot be proven. An Access List applied after
upstream selection, an externally reachable backend, a broad trusted-proxy
subnet, or a shared device bearer is not this profile.

## Memory Node installation

Create these files locally and never add their completed values to Git:

1. Copy `memory-codex-ingress.env.example` to
   `/etc/kivra-memory/memory-codex-ingress.env`. Replace every placeholder and
   install it as `root:root` mode `0600`. The listener host must be one exact
   private IP literal, never a hostname, wildcard, loopback, link-local, or
   public address. Port `8443` is fixed. The candidate-promotion identifiers
   must select one dedicated, unexpired `internal_service` binding in the same
   tenant. Its service actor and worker client must be active, the client scope
   must be exactly `memory.lifecycle.promote`, and the binding must authorize
   only `candidate_promoted`.
   The database URL is not an environment setting. Install the canonical API
   role's protected local URL at
   `/etc/kivra-memory/memory-api-database-url` for the unit's `database-url`
   systemd credential.
2. Install the existing direct-bearer pepper as
   `/etc/kivra-memory/client-token-pepper`, `root:root` mode `0600`. The unit
   exposes it only at
   `/run/credentials/kivra-memory-codex-ingress.service/client-token-pepper`.
3. Copy `kivra-memory-codex-ingress-network.conf.example` to
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

Create one Proxy Host with the exact hostname and Let's Encrypt certificate. A
shared edge is permitted, but the LAN-only/VPN-only NPM Access List must reject
other sources before upstream selection. Disable Force SSL redirects:
ScaleVault client HTTP must receive a fixed content-free rejection and must
never be proxied or redirected, because a client might otherwise send its bearer
before receiving the redirect. Route only exact HTTPS `/mcp`; every other path
must return a fixed non-redirecting rejection except NPM's static, non-proxied
`/.well-known/acme-challenge/` renewal prefix. Never rewrite or forward an
upstream redirect.

In the Proxy Host UI, keep the existing Let's Encrypt certificate, disable
Force SSL, Asset Caching, Websocket Support, and Block Common Exploits, and
attach one reviewed Access List containing source CIDRs only. Do not add
username/password entries because NPM's Basic-auth integration can consume or
clear ScaleVault's Authorization bearer. Retain `Satisfy All` as the fail-closed
Access List mode.

The Proxy Host's default upstream is deliberately unused. Point it at an NPM
loopback TCP port proven closed from inside the NPM container, so a future
generator regression fails closed instead of exposing the Memory Node.

Configure exactly one NPM Custom Location:

- location: `/mcp`;
- scheme: `http`;
- forward host: the exact private Memory Node IP;
- forward port: `8443`; and
- Advanced field: the entire contents of
  `npm-mcp-custom-location-advanced.conf.example`.

Paste the entire `npm-host-advanced.conf.example` into the Proxy Host's main
Advanced field. Its regex location rejects every path except exact `/mcp`
without colliding with NPM's generated `location /` block; NPM's
higher-priority static ACME renewal location is the only exception. NPM renders
the attached UI Access List inside the `/mcp` Custom Location, so its CIDRs
remain defined in one place. The two templates' important properties are
contractual:

- the host Advanced field defines `set_real_ip_from unix:;` and
  `real_ip_recursive off;`. Defining a server-level source list replaces NPM's
  inherited broad RFC1918 trust; because this Proxy Host accepts TCP, no caller
  can make `X-Real-IP` replace the kernel peer address used by `allow`/`deny`;
- the Custom Location's generated upstream uses scheme `http`, an exact private
  IP, and port `8443`, with no backend DNS resolution or custom CA handoff;
- `proxy_pass_request_headers off` reconstructs only the explicit request
  header allowlist in this fragment. NPM-generated `Forwarded`, `Via`,
  `X-Real-IP`, or `X-Forwarded-*` fields may still be added by the installed
  version; the application accepts them only from the exact pinned NPM peer,
  bounds and discards them before authentication, and never uses them as
  identity, authorization, source policy, tenant, actor, client, scope, or
  audit authority;
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
- access logging is disabled inside both owned locations, so rejected paths and
  query strings are not logged. Caching and body capture are also disabled. Do
  not enable debug logging or any log format containing Authorization, request
  bodies, MCP payloads, query strings, or response bodies.

Inspect NPM's generated configuration after every creation, edit, or upgrade.
If NPM cannot preserve the exact location, Access List ordering, exact private
HTTP upstream, bounded forwarding metadata, strict header reconstruction, and
no-retry behavior, do not activate the Proxy Host.

The generated Proxy Host must contain exactly one NPM-rendered `location /mcp`,
the deny-only Advanced regex location, and NPM's generated default location
pointing only to the verified-closed loopback target. The `/mcp` location must
contain the rendered source-CIDR Access List after the custom Advanced
directives, exactly one private backend `proxy_pass`, no `auth_basic`, and no
directive that clears Authorization. It must not include NPM's Force SSL
configuration or `block-exploits.conf`. A `301` client-HTTP response proves
Force SSL is still active; a backend-generated rejection for an invalid path,
query, or method proves the regex catch-all is missing or ineffective.

The generated server must also contain exactly one `set_real_ip_from unix:;`
and `real_ip_recursive off;` before its locations. If `nginx -T` shows only the
NPM-global RFC1918 `set_real_ip_from` entries, the UI Access List is bypassable:
an unapproved private-network source can supply an allowed `X-Real-IP` value and
change `$remote_addr` before `allow`/`deny`. Treat any credential-free probe that
changes from edge `403` to backend `401` after adding `X-Real-IP` as a confirmed
activation blocker.

NPM's generated Let's Encrypt handler must contain both
`location ^~ /.well-known/acme-challenge/`, which uses only its dedicated
static webroot with authentication disabled and `allow all`, and
`location = /.well-known/acme-challenge/`, which returns `404`. Neither may
contain `proxy_pass`, an application rewrite, dynamic execution, or a directory
listing. A valid provisioned token may return `200`; the directory path and a
nonexistent token must return `404` without changing the Memory backend
counter. The generated configuration, not that counter, proves the handler is
static-only and has no upstream. Record the exact installed NPM and Nginx
versions and, where available, the immutable NPM container image digest with
this evidence so an upgrade cannot silently change the ordering assumptions.

Inspect the complete `nginx -T` output, not only this Proxy Host's location.
Global `real_ip_header`, `set_real_ip_from`, `real_ip_recursive`,
`proxy_protocol`, `geo`, `map`, and included Access List directives can rewrite
the address used by `allow`/`deny` before location processing. The LAN/VPN gate
must remain based on an authenticated immediate edge peer or the kernel source
address; caller-supplied `Forwarded`, `X-Forwarded-For`, or `X-Real-IP` must not
turn an unapproved source into an approved one.

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
   exact private HTTP backend IP, no upstream retry, no upstream redirect, and
   bounded timeouts.
4. Normal Let's Encrypt validation succeeds on the client HTTPS hop. Wrong
   client TLS hostname, wrong Host, wrong Origin, query strings, trailing
   slashes, and every non-`/mcp` HTTPS application path fail without an
   application redirect. ADR 0026's static ACME prefix is tested separately.
   Forwarding headers from the pinned NPM peer do not change the request's
   canonical identity or authority.
5. A valid per-device bearer can initialize, read, and mutate. No bearer and a
   revoked bearer fail. Revoking one device blocks its next request without
   affecting another device or ChatGPT.
6. A GET/SSE connection ends at the reviewed lifetime and reconnects normally.
   A deliberately failed mutation is never retried.
7. A canary scan of NPM and service logs finds no Authorization value, MCP body,
   memory payload, query string, or response body.
8. Stopping the tunnel does not affect private Codex access, and stopping the
   private ingress does not affect the tunnel.
9. From a non-VPN external network, every ScaleVault application probe to each
   candidate public IP either has no route or returns a fixed content-free
   pre-upstream rejection for client HTTP and HTTPS requests using the
   configured hostname as explicit SNI and Host. ADR 0026's static ACME prefix
   is excluded from this application-route assertion. Status codes need not
   match because scheme and ACL rejections occur in different Nginx phases.
   Client HTTP application requests must never redirect. An independent backend
   connection or firewall counter must remain at zero throughout those probes.
   Also inspect edge firewall, NAT, UPnP, NPM container port publication, and
   wildcard Proxy Hosts. Private DNS absence alone is not proof.
10. Repeat the external HTTPS `/mcp` rejection with spoofed LAN values in
    `Forwarded`, `X-Forwarded-For`, and `X-Real-IP`. The response and backend
    connection/firewall counters must be identical to the unspoofed rejection,
    proving NPM did not rewrite Access List authority from caller headers.
11. Repeat the same spoof probes from an unapproved LAN/VPN source. Inherited
    private-network real-IP trust must not turn spoofed allowed-source values
    into Access List authority, and backend counters must remain at zero.
12. Probe the static ACME prefix with the directory path and a nonexistent
    token over HTTP and HTTPS. Each returns `404` without redirecting or changing
    the Memory backend counter. Generated configuration must show the distinct
    `^~` static-token location and exact-directory `404` location and proves
    both contain no upstream or application rewrite.

Repository tests cannot establish firewall, NPM, DNS, client certificate, NAT, or
internet reachability state. Keep a dated, sanitized live acceptance record;
external coordinates remain live configuration rather than repository data.
