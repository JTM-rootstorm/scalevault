# Milestone 0 capability probe

- Observation date: 2026-08-03 (America/Chicago)
- Status: Partially complete; account-side ChatGPT and GitHub ingress checks remain

This record separates documentation claims, observations from the installed
environment, and checks that require account or repository configuration.

## Capability matrix

| Capability | Result | Evidence |
|---|---|---|
| Codex Streamable HTTP MCP | Verified | Codex CLI 0.146.0 initialized the private echo endpoint and called its `echo` tool through a temporary SSH forward. |
| Codex MCP policy controls | Verified | The installed CLI and current manual support bearer-token environment variables, required servers, timeouts, tool allow/deny lists, and per-tool approval modes. |
| ChatGPT Pro custom MCP | Documented read/fetch only | Full custom MCP write/modify support is currently documented for Business, Enterprise, and Edu. Pro may connect MCPs with read/fetch permissions in developer mode. |
| ChatGPT custom MCP on mobile | Unsupported | OpenAI documents MCP apps as web-only. |
| Secure MCP Tunnel | Documented; account test pending | The outbound-only tunnel supports private MCP connectivity and developer-mode testing. A tunnel ID, runtime API key, organization permissions, and ChatGPT association are required. |
| Public plugin through Secure MCP Tunnel | Unsupported | OpenAI requires a stable publicly reachable HTTPS MCP endpoint for public submission. |
| GitHub append-only proposal creation | API contract verified; repository pending | The Contents API can create a unique path with `Contents: write`; the deployment has no dedicated private ingress repository yet. |
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

Primary sources:

- [Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt-beta)
- [Plugins in ChatGPT and Codex](https://help.openai.com/en/articles/20001256-plugins-in-chatgpt-and-codex)
- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [Build an MCP server](https://developers.openai.com/plugins/build/mcp-server)
- [Submit plugins](https://developers.openai.com/plugins/deploy/submission)

## GitHub ingress observation

No dedicated private ingress repository was found. A future repository should
be isolated from the public source repository and the private Forgejo archive.

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

## Pending account and repository checks

Milestone 0 remains open until the following external checks are complete:

- confirm that the target Pro account exposes developer mode and custom-app
  creation;
- confirm tunnel Read, Manage, and Use permissions in the intended Platform
  organization;
- create and associate a tunnel, then discover and invoke `echo` in a fresh
  ChatGPT web conversation;
- verify that a mutation tool is unavailable or rejected for the Pro account;
- confirm the expected native-mobile absence;
- select and create the dedicated private GitHub ingress repository;
- grant the connected GitHub app access and create one harmless immutable test
  proposal; and
- fetch and validate that proposal through the minimal ingress probe.
