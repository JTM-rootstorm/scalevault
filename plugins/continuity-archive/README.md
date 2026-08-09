# Continuity Archive private profile

This package defines the Milestone 8 private ChatGPT web profile. It retrieves
continuity through a user-controlled Memory Node reached by Secure MCP Tunnel.
The package contains no endpoint, repository coordinate, credential, or
user-specific identity.

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
