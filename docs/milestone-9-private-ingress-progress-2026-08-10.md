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

## Open activation gate

The separately managed reverse proxy reaches the HTTP backend. Its route guards,
authenticated direct-private path, bounded SSE lifetime, revocation, observed
connect-failure behavior, and LXC-side payload-log canaries pass.

Milestone acceptance remains open on evidence that cannot be collected from the
current NPM UI or approved client vantage:

1. The operator cannot currently obtain a shell or complete `nginx -T` output
   from the containerized NPM deployment. Generated Custom Location ordering,
   source ACL rendering, real-IP configuration, static-only ACME handling, and
   the installed NPM/Nginx versions and image digest therefore remain
   unverified.
2. A genuinely external source and an unapproved LAN/VPN source must repeat the
   baseline and spoofed `Forwarded`, `X-Forwarded-For`, and `X-Real-IP` probes
   while the backend counter remains unchanged. The approved LAN workstation
   cannot prove that the edge ACL resists an allowed-address spoof.
3. NPM access, error, and container logs must be scanned for the same canaries.
   The completed zero-match scan covers only the Memory API and ingress
   journals.
4. An actual Codex client should observe reconnect after the five-minute SSE
   lifetime. The completed raw transport probe proves a fresh authenticated GET
   succeeds, not client-specific automatic reconnect behavior.
5. A live ChatGPT Web read through the unchanged Secure MCP Tunnel remains an
   account-side gate. Repository and host evidence proves tunnel readiness and
   isolation but cannot substitute for that client observation.

The unavailable generated proxy configuration remains a documented evidence
gap rather than an inferred pass. The live results above establish current
behavior only; they do not prove future NPM regeneration preserves it.
