# Continuity Archive profiles

This package preserves the Milestone 8 private ChatGPT web profile and defines
an operator-neutral Milestone 9 public relay read candidate. Both retrieve
continuity from a user-controlled Memory Node. The package contains no endpoint,
repository coordinate, credential, registered app identifier, or user-specific
identity.

## Private tunnel profile

The operator configures the tunnel-backed private app outside this package and
compares its discovered tools with
`profiles/chatgpt-pro-private.json`. Enable the profile only when the discovered
set is an exact match and every tool has the required read-only annotations.
Do not publish, connect, or approve the nomination and mutation tools listed in
`forbidden_tools` for this profile.

ChatGPT uses a frozen tool snapshot. After the MCP server changes tools or tool
metadata, refresh the private app and repeat the exact comparison before using
it again. Leave the profile disabled while its snapshot is stale.

The standard ChatGPT GitHub integration is read-only and does not provide this
fallback. The optional workflow is disabled by default. Enable it only when a
current account-side capability probe verifies an exact create-file action and
the user explicitly approves each proposal action. Configure the private
ingress repository and canonical installation, persona, branch, and subject
identifiers outside this package. A verified action may create one new
proposal-v2 file, but it may never update or delete a proposal or claim that a
proposal is canonical memory.

ChatGPT custom MCP availability and supported surfaces can change. Re-probe the
live account before activation and after any app or server-tool refresh. Disable
the profile if the live surface cannot enforce the pinned read-only tool set.

## Public relay read candidate

`profiles/chatgpt-public-relay-read.json` describes a read-only public plugin
candidate without embedding a relay address. An operator must separately deploy
the relay, register its production MCP connection, and complete OAuth and
installation binding. This repository intentionally does not include `.app.json`
until a real connection is registered and available for testing.

The candidate begins in the disabled `chatgpt_public_plugin_detected` state. It
may activate the `chatgpt_public_plugin_read` profile only when OAuth succeeds,
the authenticated identity has the intended installation binding, the relay is
online, and current discovery confirms exactly the configured read tools and
annotations. Unknown tools, stale metadata, unknown identity, failed OAuth, or
relay outage keep the profile disabled. The relay is a transport and must not
persist memory bodies.

`chatgpt_public_plugin_full` is a dormant capability state, not a claim about a
current ChatGPT plan or app. It may activate only after an explicit current
capability probe verifies direct writes and discovery exposes exactly the
complete read and mutation set. Otherwise the profile remains disabled; plugin
installation alone cannot establish write permission.

The public candidate is not submission-ready without a real registered endpoint,
published operator policies, reviewer access, and live capability evidence. The
private tunnel profile remains independently usable if relay deployment or
public submission never occurs.
