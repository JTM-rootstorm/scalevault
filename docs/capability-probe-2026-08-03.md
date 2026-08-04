# Milestone 0 capability probe

- Observation date: 2026-08-03 (America/Chicago)
- Status: Complete

This record separates documentation claims, observations from the installed
environment, and checks that require account or repository configuration.

## Capability matrix

| Capability | Result | Evidence |
|---|---|---|
| Codex Streamable HTTP MCP | Verified | Codex CLI 0.146.0 initialized the private echo endpoint and called its `echo` tool through a temporary SSH forward. |
| Codex MCP policy controls | Verified | The installed CLI and current manual support bearer-token environment variables, required servers, timeouts, tool allow/deny lists, and per-tool approval modes. |
| ChatGPT Pro custom MCP | Read-only echo verified | After developer mode was enabled, a private custom app discovered and invoked the tunneled `echo` tool in ChatGPT web. The operator observed the exact result `chatgpt tunnel echo verified`. |
| ChatGPT custom MCP on mobile | Unsupported | OpenAI documents MCP apps as web-only. |
| Secure MCP Tunnel | End-to-end verified | Official `tunnel-client` 0.0.10 fetched tunnel metadata, started control-plane polling, initialized the private MCP server, and carried the successful ChatGPT web `echo` invocation through its loopback-only systemd unit. |
| Public plugin through Secure MCP Tunnel | Unsupported | OpenAI requires a stable publicly reachable HTTPS MCP endpoint for public submission. |
| GitHub append-only proposal creation | Verified | The dedicated private repository returned `201 Created`, exact bytes on fetch, and `422` for a duplicate create without `sha`. The connected GitHub app also created a unique proposal that the pinned read-only client fetched byte-for-byte. |
| Debian Memory Node foundation | Verified | Debian 13, PostgreSQL 17.10, pgvector 0.8.0, Python 3.13.5, Go 1.24.4, Node 20.19.2, pnpm 10.15.0, protobuf 3.21.12, and uv 0.11.25 were observed on the live node. |
| Relay and node-agent streamed echo | Verified | An in-memory gRPC transport streamed two response chunks and propagated an explicit cancellation acknowledgement through the generated relay contract. |

## Codex observation

The installed Codex CLI is version 0.146.0. Its documented Streamable HTTP
configuration supports the planned private-client profile:

```toml
[mcp_servers.kivra_memory]
url = "https://memory.example/mcp"
bearer_token_env_var = "KIVRA_MEMORY_TOKEN"
required = true
enabled_tools = ["memory_context", "memory_search"]
default_tools_approval_mode = "writes"
startup_timeout_sec = 10
tool_timeout_sec = 60
```

The Milestone 0 test started the loopback-only Memory Node, forwarded it through
SSH, registered the temporary endpoint in a fresh Codex process, and received
the exact result `codex remote echo verified`. The temporary registration and
forward were removed after the test.

Primary source: [Codex Model Context Protocol configuration](https://learn.chatgpt.com/docs/extend/mcp).

## ChatGPT and Secure MCP Tunnel observations

Current OpenAI documentation establishes these boundaries:

- Pro custom MCP access is read/fetch-only; do not expose mutation tools to it.
- Custom MCP apps are available on ChatGPT web, not native mobile.
- Plugin visibility or publication does not grant the underlying app permission
  or guarantee invocation on every plan and surface.
- Secure MCP Tunnel keeps the private server off the public internet and can
  forward Streamable HTTP and server-sent events.
- Secure MCP Tunnel cannot be the endpoint for a public plugin submission.

The target Pro account initially showed no custom-app creation control because
developer mode was disabled. After the operator enabled developer mode, they
created the private app and invoked the tunnel-backed, non-mutating `echo` tool
from ChatGPT web. The operator observed the exact result
`chatgpt tunnel echo verified`. This is account-side acceptance evidence; the
Codex-run host checks below independently establish the tunnel runtime and MCP
server behavior.

Primary sources:

- [Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt-beta)
- [Plugins in ChatGPT and Codex](https://help.openai.com/en/articles/20001256-plugins-in-chatgpt-and-codex)
- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [Build an MCP server](https://developers.openai.com/plugins/build/mcp-server)
- [Submit plugins](https://developers.openai.com/plugins/deploy/submission)

## GitHub ingress observation

The dedicated private repository is `JTM-rootstorm/scalevault-memory-ingress`,
numeric repository ID `1322346959`, with default branch `main`. It is isolated
from the public source repository and the private Forgejo archive. Its README
defines the privacy boundary and its schema file is byte-identical to the
locked project schema.

The proposal client will:

1. create a unique `ingress/v1/<installation>/<year>/<month>/<uuid>.json` path;
2. supply an explicit branch and omit `sha` so the request is create-only;
3. accept only HTTP `201 Created` as a new proposal;
4. resolve ambiguous network results by reading and byte-comparing the path;
5. fail closed if the existing bytes differ; and
6. never update or delete a proposal object.

GitHub permissions are repository-wide rather than prefix-scoped. Immutability
therefore depends on an isolated repository, unique paths, least-privilege app
access, client behavior, and audit history.

Primary source: [GitHub repository contents API](https://docs.github.com/en/rest/repos/contents?apiVersion=2022-11-28#create-or-update-file-contents).

The dated acceptance object was created at a unique path through the Contents
API with no `sha`; GitHub returned `201 Created`. A read-only client pinned the
repository ID, owner/name, `main`, installation root, decoded size, and Git blob
SHA, then returned bytes matching the submitted object's SHA-256 digest. A
second create at the same path, again without `sha`, returned `422` and made no
change.

The connected GitHub app initially returned `404` before the new repository was
added to its selected-repository scope. After that permission was granted, the
app created a second unique, schema-valid proposal. The pinned read-only client
fetched all 764 bytes, validated the Git blob metadata, and produced the exact
expected SHA-256 digest.

## Relay and node-agent observation

The generated `relay-v1.proto` bindings were exercised over a bidirectional
gRPC stream. The relay sent a fixed `POST /echo` request in two body frames,
the node agent returned two distinct response frames, and the caller observed
the original combined bytes. A separate request propagated cancellation and
received an explicit acknowledgement with the same reason.

The probe accepts no arbitrary destination or forwarded headers, caps each
chunk at 64 KiB and the complete body at 256 KiB, and verifies installation,
connection, request, and trace identifiers on both directions. Race-enabled
tests, vetting, and deterministic CGO-disabled service builds passed.

## Debian observation

The live node matches the selected application stack. PostgreSQL data resides
on the mounted persistent storage, while the database and project services are
stopped and disabled between milestone probes. Required extension control files
for vector, trigram, citext, and pgcrypto are present.

Debian 13 does not provide the plan's `postgresql-contrib` meta-package name in
the configured repositories; the required contrib extensions ship with the
PostgreSQL 17 packages. The root filesystem is smaller than the plan's target,
but persistent storage is a separate 70 GiB NFS share.

Primary sources:

- [Debian PostgreSQL package](https://packages.debian.org/trixie/postgresql)
- [Debian pgvector package](https://packages.debian.org/trixie/postgresql-17-pgvector)
- [Debian Go package](https://packages.debian.org/trixie/golang-go)
- [Debian Python package](https://packages.debian.org/trixie/python3.13)

## Secure MCP Tunnel host observation

Official `tunnel-client` 0.0.10 was downloaded for Linux amd64, verified against
the release's `SHA256SUMS.txt`, and installed at `/usr/local/bin/tunnel-client`.
The native systemd verifier accepted `kivra-memory-tunnel.service`. With its
tunnel identifier and restricted runtime credential staged, the unit fetched
the correct tunnel metadata, started polling, and initialized the private MCP
server using protocol version `2025-06-18`.

The unit runs as `memory-tunnel`, forwards only to
`http://127.0.0.1:8080/mcp`, and keeps its health and admin UI on
`127.0.0.1:8081`. The runtime key is loaded as a systemd credential from a
root-readable local file. It must not be stored on the NAS while that export's
ACL grants broad modify access.

The service is active but remains disabled during acceptance testing. Both the
Memory API and tunnel health interface listen only on loopback. The tunnel
reports `live` and `ready`, with zero service restarts observed.

`tunnel-client doctor` 0.0.10 reports the absent OAuth metadata as a failure,
even for its documented `sample_mcp_remote_no_auth` profile. The running
client's readiness logic correctly treats the OAuth discovery failure as
optional for this plain MCP server; MCP initialization and control-plane
metadata retrieval provide the runtime evidence. This discrepancy is recorded
as a client diagnostic false negative rather than hidden or worked around with
fabricated OAuth metadata.

Primary sources:

- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [Official tunnel-client releases](https://github.com/openai/tunnel-client/releases/latest)

## Milestone conclusion

Milestone 0 is complete. Codex and ChatGPT web both invoked the private
non-mutating echo server through their intended paths, the relay/node-agent
probe preserved streaming and cancellation, the GitHub ingress path enforced
create-only behavior, and the live Debian package and service assumptions were
verified. The ChatGPT test server exposed only `echo`; it did not offer a
mutation tool or test direct custom-MCP writes. The connected GitHub app
separately demonstrated the planned append-only proposal-write fallback.
