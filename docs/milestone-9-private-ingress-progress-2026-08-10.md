# Milestone 9 private-ingress progress

Milestone 9 was rescoped by ADR 0022 and ADR 0024 to keep ChatGPT Web on the
outbound Secure MCP Tunnel and give owner-controlled Codex devices a separate
direct-private HTTPS ingress. This record is a progress checkpoint, not
Milestone 9 acceptance.

## Repository evidence

- The dedicated direct-only ingress, process-profile separation, hard request
  lifetimes, deployment profile, and private topology ADR are committed through
  `07b27d6`.
- The ingress exposes only exact `/mcp`, accepts only Streamable HTTP `GET`,
  `POST`, and `DELETE`, and retains ADR 0018 bearer authentication on every
  request.
- After exact proxy-peer validation, the application bounds and discards NPM
  forwarding metadata before authentication. It rejects untrusted proxy peers,
  ambiguous authority headers, oversized requests, aliases, redirects, and
  non-HTTP ASGI scopes before canonical dispatch.
- Spawned-process key-provider tests cover provision/provision,
  provision/destroy, get/destroy, and interrupted-publication races without
  material resurrection or temporary-file residue.
- The latest development-host gate passed 1,207 Python tests with 172
  PostgreSQL tests skipped because that host lacks the required `vector`
  extension. Ruff, mypy, Go vet/tests/build determinism, protobuf determinism,
  and JSON schemas passed. The top-level `make verify` stopped only because
  `pnpm` is not installed; the equivalent package-local npm check and test
  commands passed.
- The authoritative unprivileged LXC PostgreSQL 17 lane passed all 187
  integration tests with the required extension gate enabled and zero skips.

## Sanitized live evidence

- Immutable release `48a6e4f` was installed without deleting the prior release.
- The canonical Memory API remained loopback-only and the Secure MCP Tunnel
  remained active throughout deployment.
- The ingress now serves HTTP on one exact private address and port 8443 with
  no wildcard listener. Client-facing Let's Encrypt termination remains at NPM.
- The service is pinned to one exact proxy host route in both systemd IP policy
  and the application configuration.
- An independent persistent firewall permits port 8443 from that proxy route
  and drops other sources. A direct LAN probe incremented only the drop
  counter, while a proxy-originated probe incremented only the allow counter.
- The five temporary backend certificate and operator-CA artifacts were
  permanently removed after the HTTP listener became active. Application
  credentials remain only in protected live configuration.
- The canonical API, ChatGPT tunnel, and private ingress were all active after
  the isolated ingress restart.
- After the NPM upstream changed to HTTP, credential-free HTTPS requests to
  exact `/mcp` returned the expected application `401`, proving the approved
  NPM route reaches the private HTTP listener without forwarding credentials.
- NPM now owns one `/mcp` Custom Location so its existing source-CIDR Access
  List remains the single source of truth. A non-conflicting regex catch-all
  is configured to reject every other application path; the representative
  probes below passed. The configured higher-priority static ACME renewal
  prefix is the intended non-application exception; complete generated-config
  verification remains open below.
- Client HTTP `/mcp`, operator paths, trailing slashes, query strings, and
  unsupported methods returned fixed `404` or `405` responses without
  redirects. The backend firewall counter remained unchanged across those
  probes, then increased only for exact HTTPS `/mcp` as it returned `401`.
- The canonical API, ChatGPT tunnel, and private ingress remained active, and
  tunnel readiness remained `ready`, after the edge changes.
- HTTP and HTTPS probes for the ACME directory and a nonexistent challenge
  token returned `404` without redirects, and the Memory backend counter stayed
  unchanged, confirming those probes did not contact the Memory backend.
- A short-lived, least-privilege direct-private credential initialized through
  NPM, discovered the required tools, reported the expected transport, passed
  an authorized nonexistent-memory read, and completed the fixed write canary
  with an `omit` outcome.
- The write canary added exactly one selection decision and one command receipt
  while adding zero memory events, memories, or outbox jobs.
- Revoking that credential caused its immediately following request to fail
  authentication. Both disposable acceptance credentials are revoked, no
  acceptance credential remains active, and all protected scratch artifacts
  were removed.
- An authenticated SSE GET returned `200`, produced its first byte in 0.295
  seconds, streamed 855 bytes, and closed after 300.229 seconds. A fresh GET
  then returned `200`, produced its first byte in 0.326 seconds, and streamed
  45 bytes before the client deliberately closed it after 20 seconds.
- During a controlled connect-failure probe, only the Codex ingress stopped.
  One credential-free POST returned `502` and produced exactly one accepted
  backend connection attempt. The ingress restarted immediately; the canonical
  API and ChatGPT tunnel remained active and tunnel readiness remained `ready`.
  This proves the observed connect-failure case, not response loss after a
  canonical commit.
- A rejected query canary returned `404` without backend contact, a fake bearer
  returned `401`, and an authenticated JSON-RPC marker returned `200` with its
  identifier echoed. The Memory API and ingress journals contained zero matches
  for the real bearer, marker, or synthetic nomination text.
- This non-NPM LAN workstation could not connect directly to the backend.
  Caller-supplied `Forwarded` and `X-Forwarded-For` values gained no authority
  and reached only the normal `401` boundary; caller-supplied `X-Real-IP`, alone
  or combined with the other fields, failed closed with `403`.
- The canonical API, ChatGPT tunnel, and Codex ingress were active, tunnel
  readiness was `ready`, and no protected acceptance scratch directories
  remained after all live probes.

## Open acceptance gates

The separately managed reverse proxy reaches the HTTP backend. Its route guards,
authenticated direct-private path, bounded SSE lifetime, revocation, observed
connect-failure behavior, and LXC-side payload-log canaries pass.

Subsequent SSH access to the NPM LXC made generated configuration inspection
possible. `nginx -T` passed and the protected temporary dump was deleted after
review. The running container reports NPM 2.12.6, OpenResty 1.27.1.2, and image
ID `sha256:405c49a2d38c1c10fb4a99317d1a2b873b11732b62ad05079ce31566f0f553a1`.
The generated host has the exact private backend, source-only Access List,
`satisfy all`, bounded request and response behavior, disabled retry and
redirect handling, static-only ACME locations, and zero canary matches in its
access log, error log, and container output.

That inspection also found two activation blockers:

- Block Common Exploits remains enabled at both server and `/mcp` scope, so
  server rewrite responses can bypass the owned fixed-rejection and logging
  behavior.
- NPM globally trusts `X-Real-IP` from all RFC1918 networks with recursive
  rewriting. A credential-free request from an unapproved source returned edge
  `403` with no backend packets, while the same source supplying an allowed
  `X-Real-IP` returned backend `401` and contacted the Memory Node. This is a
  confirmed Access List bypass.

Both activation blockers were remediated and reverified. Block Common Exploits
was disabled, and the host Advanced configuration replaced inherited TCP
real-IP trust with `set_real_ip_from unix:;` plus
`real_ip_recursive off;`. A fresh `nginx -T` passed and showed each directive
exactly once, no `block-exploits.conf` include, the `/mcp` Custom Location, and
the application-path catch-all. From the same unapproved source used to prove
the original bypass, baseline and spoofed `Forwarded`, `X-Forwarded-For`, and
`X-Real-IP` requests all returned edge `403`. A temporary non-blocking firewall
counter recorded zero new backend connections during those probes and was
removed automatically. From an approved source, exact HTTPS `/mcp` still
reached the application's uniform `401`; invalid path, query, and client HTTP
application requests returned fixed `404` with no redirect. The canonical API,
Codex ingress, and Secure MCP Tunnel services remained active.

Milestone acceptance remains open until:

1. A genuinely external source repeats the baseline and spoofed `Forwarded`,
   `X-Forwarded-For`, and `X-Real-IP` gate with zero backend connections.
2. A fresh authenticated canary permits NPM logs to be searched for the exact
   bearer before its protected artifact is destroyed. Existing NPM and LXC
   marker and payload scans have zero matches.
3. An actual Codex client observes reconnect after the five-minute SSE
   lifetime. The completed raw transport probe proves a fresh authenticated GET
   succeeds, not client-specific automatic reconnect behavior.
4. A live ChatGPT Web read through the unchanged Secure MCP Tunnel passes. This
   remains an account-side gate; repository and host evidence proves tunnel
   readiness and isolation but cannot substitute for that client observation.

The private ingress activation blockers are closed. The remaining items are
acceptance evidence rather than known configuration defects.
