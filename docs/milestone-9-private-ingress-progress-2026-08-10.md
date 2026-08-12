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
- The latest development-host gate passed 1,212 Python tests with 172
  PostgreSQL tests skipped because that host lacks the required `vector`
  extension. Ruff, mypy, Go vet/tests/build determinism, protobuf determinism,
  and JSON schemas passed. The top-level `make verify` stopped only because
  `pnpm` is not installed; the equivalent package-local npm check and test
  commands passed.
- The authoritative unprivileged LXC PostgreSQL 17 lane passed all 187
  integration tests with the required extension gate enabled and zero skips.
- The direct runtime now requires and installs one server-owned, UUIDv7-pinned
  candidate-promotion identity. Production configuration is all-or-none and
  the provider can supply only the configured actor, client, binding, tenant,
  and exact `memory.lifecycle.promote` scope.
- Candidate-lifecycle projection loading retains the existing memory-row lock
  but does not request UPDATE privilege merely to prove that newly allocated,
  immutable evidence UUIDs are absent. The regression test freezes both sides
  of that least-privilege boundary.

## Sanitized live evidence

- Immutable release `93d9b2d` is active. Releases `48a6e4f` and `7df898c` remain
  retained for recovery and defect provenance.
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
- The operator repeated the application-path suite from a genuinely external
  source outside the NPM Access List. Baseline and spoofed forwarding-header
  requests returned the expected fixed `503` rejection, completing the external
  source gate without granting backend reachability.
- An actual Codex CLI 0.147.0 TUI initialized through NPM with a short-lived
  status-only direct-private credential. The same client session called
  `memory_transport_status` successfully before and after 330 seconds idle;
  both calls reported the direct-private transport and active binding.
- The Codex client held zero established backend connections while idle. It did
  not open the standalone GET/SSE subscription exercised by the raw transport
  probe, so no five-minute stream existed for this client to reconnect. The
  post-idle tool call used a fresh authenticated request and succeeded without a
  retry storm or client-visible disconnect.
- The Codex-session credential recorded successful use, was revoked after the
  test, failed its immediately following request with `401`, and left no local
  or LXC-side credential scratch artifacts. The canonical API, Codex ingress,
  and Secure MCP Tunnel remained active.
- A fresh status-only bearer initialized through NPM. While the exact bearer
  still existed in protected scratch, its full value had zero matches in the
  NPM access log, error log, and complete container output. The credential was
  then revoked, its next request returned `401`, and every local, Memory-LXC,
  and NPM-LXC bearer artifact was permanently removed.
- The operator accepted the same-session Codex continuity result together with
  the completed raw SSE lifetime probe as satisfying the Codex-session gate.
- Preparation for the ChatGPT Web read created one sensitivity-zero,
  private-root candidate through the direct-private ingress. A distinct
  search-capable client retrieved the exact candidate with candidate inclusion
  enabled. Its corroborating nomination then failed closed with
  `dependency_unavailable` and rolled back because the direct runtime did not
  yet have a server-owned promotion-principal provider wired into its selection
  engine.
- The preparation attempt added exactly one event, memory, evidence record,
  selection decision, command receipt, and four outbox jobs. The retained
  revision-one candidate had a bounded expiry deadline and remained invisible
  to the unchanged ChatGPT tunnel, whose read capability excludes candidates.
  All three preparation credentials were revoked, returned `401` afterward,
  and left no local or LXC-side credential scratch artifacts.
- The pinned promotion-provider release and a dedicated active service actor,
  worker client, and `internal_service` binding were then installed. The client
  is scoped exactly to `memory.lifecycle.promote`; the binding authorizes only
  `candidate_promoted` and has no installation or expiry.
- A rollback-only live diagnostic proved the promotion identity and event append
  were valid, then exposed SQLSTATE `42501` when projection loading attempted an
  unnecessary UPDATE lock on immutable, newly allocated evidence. That probe
  produced no durable changes. Release `93d9b2d` removed only that lock and a
  second rollback-only run completed every promotion stage successfully.
- A fresh, distinct direct-private client then corroborated the candidate
  through NPM. The canonical selection path promoted the existing memory to
  active revision two. The exact database delta was one event, one evidence
  record, one selection decision, one command receipt, and two outbox jobs,
  with no new memory row; the event operation is `candidate_promoted`.
- An authenticated `memory_get` through both the direct-private ingress and the
  unchanged local `/chatgpt/mcp` Secure Tunnel route returned the same active
  revision-two memory. The disposable direct credential was revoked, its next
  ingress request returned `401`, and every local and LXC-side promotion probe,
  bearer, SQL, archive, and environment-backup scratch artifact was removed.
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

The genuinely external source, exact-bearer log, Codex-session, pinned
promotion-identity, canonical promotion, and host-side Secure Tunnel read gates
are complete. Milestone acceptance remains open only for the account-side live
ChatGPT Web read through the unchanged Secure MCP Tunnel; repository and host
evidence cannot substitute for that client observation.

The private ingress activation blockers and runtime-composition defect are
closed. The final account-side acceptance read is the only remaining item.
