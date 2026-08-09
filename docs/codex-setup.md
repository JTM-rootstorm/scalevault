# Codex setup

ScaleVault connects to local Codex clients over Streamable HTTP MCP. The ChatGPT
desktop app, Codex CLI, and Codex IDE extension share MCP configuration on the
same Codex host. ChatGPT on the web does not read this local configuration.

The current OpenAI references are:

- [Model Context Protocol](https://developers.openai.com/codex/mcp/)
- [Codex configuration reference](https://developers.openai.com/codex/config-reference/)
- [Custom instructions with AGENTS.md](https://developers.openai.com/codex/guides/agents-md/)

The configuration syntax below was also checked against the installed Codex CLI
0.147.0 with `codex mcp add --help`. Recheck it when upgrading Codex.

## Choose the configuration scope

Use `~/.codex/config.toml` when the same ScaleVault identity should be available
to all trusted workspaces on the host. Use `.codex/config.toml` only inside a
trusted project and do not commit a private endpoint or identity-specific
configuration.

Copy one template and replace its placeholder URL:

- [`deploy/codex/private-direct.config.toml.example`](../deploy/codex/private-direct.config.toml.example)
- [`deploy/codex/relay.config.toml.example`](../deploy/codex/relay.config.toml.example)

The direct template is the supported private-node route. The relay template is
disabled by default and is an activation example only; keep it disabled until
relay authentication, installation binding, and end-to-end acceptance have
passed.

`bearer_token_env_var` names an environment variable. It does not contain the
credential itself. Supply that variable to the process that launches Codex, the
IDE, or the desktop app through the host's secret manager. Never put a token in
TOML, shell history, an `AGENTS.md`, or the repository.

`required = true` makes Codex startup fail when the enabled server cannot
initialize. The Memory Node must also reject missing or invalid authorization;
Codex can otherwise attempt an unauthenticated connection when the configured
credential variable is absent.

## Install reusable instructions

Merge [`deploy/codex/AGENTS.md.example`](../deploy/codex/AGENTS.md.example) into
the applicable global or project `AGENTS.md`. Keep its untrusted-memory rule
intact. Repository-local guidance may add narrower scope or approval rules but
must not turn retrieved memory into authority or instructions.

Codex reads the MCP server `instructions` field during initialization. The
server's first 512 characters must independently state its most important
constraints because Codex may use that prefix while deciding whether to invoke
the server.

## Confirm discovery

Restart the local Codex client after changing configuration. Then run:

```console
$ codex mcp list
```

Confirm `kivra_memory` is enabled. In the Codex terminal UI, `/mcp` should show
the same active server. These checks prove configuration discovery, not
authorization or memory access.

## Run safe diagnostics

Install the project package, then supply the endpoint, bearer token, and the
provisioned UUIDv7 persona and branch identifiers through the environment. The
diagnostic never reads Codex configuration and never prints the endpoint,
token, remote exception text, memory content, client ID, or credential ID.

```console
$ export KIVRA_MEMORY_MCP_URL='https://memory.private.example/mcp'
$ read -rs KIVRA_MEMORY_TOKEN && export KIVRA_MEMORY_TOKEN
$ export KIVRA_MEMORY_PERSONA_ID='00000000-0000-7000-8000-000000000000'
$ export KIVRA_MEMORY_BRANCH_ID='00000000-0000-7000-8000-000000000000'
$ kivra-memory-diagnose --expected-transport direct_private
```

Replace the example UUIDs with identifiers issued by ScaleVault provisioning;
do not invent them. The default run verifies:

1. authenticated MCP initialization and exact ScaleVault server identity;
2. discovery of the required public tools;
3. the coarse `memory_transport_status` identity (`direct_private`,
   `secure_tunnel`, or `relay`) and compatible installation state; and
4. read authorization by requesting a generated nonexistent memory UUID and
   requiring a payload-free `not_found` result.

Output is a stable JSON object containing only check names, pass/fail/skip
states, and allowlisted codes. Ordinary MCP status intentionally does not expose
client or credential identity. Validate those identifiers only through a
separate authenticated administrative diagnostic when one is available.

### Opt-in write canary

The write canary has two explicit opt-ins. It also requires an existing project
subject UUIDv7 from provisioning; it never invents a subject or logical session.

```console
$ export KIVRA_MEMORY_CANARY_SUBJECT_ID='00000000-0000-7000-8000-000000000000'
$ kivra-memory-diagnose \
    --expected-transport direct_private \
    --write-canary \
    --confirm-write-canary nominate-routine-banter-and-require-omit
```

The canary submits fixed synthetic `routine_banter` through `memory_nominate`.
Success requires an `omit` receipt with no event, memory, revision, or outbox
effect, so there is nothing to clean up. `reject` is a failed canary. Any
candidate, active, promoted, or otherwise linked result is a hard failure. When
an anomalous durable result contains a valid synthetic memory ID and revision,
the JSON adds `recovery_required`; give that reference to an authorized operator
for explicit logical-forget recovery. The diagnostic does not issue another
mutation automatically after an unexpected policy result.

For a future relay route, use `--expected-transport relay` only after enabling
the relay template and completing its activation gates.

## Interpret failures

- `authentication_rejected`: the endpoint returned HTTP 401 or 403. Check the
  injected credential and its revocation state without printing it.
- `connection_failed`: TLS, routing, timeout, protocol initialization, or a
  sanitized transport failure prevented a result.
- `unexpected_server` or `required_tools_missing`: the URL does not expose the
  expected ScaleVault MCP contract.
- `unexpected_transport` or `unexpected_installation_state`: the connection
  arrived through a different trust path than configured.
- `forbidden`: the credential lacks the tested read or nomination capability.
- `dependency_unavailable`: authentication succeeded but a required server-side
  dependency was unavailable.
- `recovery_required`: the omission canary unexpectedly produced a durable
  memory; stop write testing and use the returned synthetic ID/revision for
  operator-controlled cleanup.

Unset the four or five `KIVRA_MEMORY_*` variables when the diagnostic session is
finished. Rotating or revoking the credential remains an administrative action;
this CLI does not modify authentication state.
