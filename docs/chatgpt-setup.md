# ChatGPT setup

ChatGPT integration is capability-gated. Private read access, direct writes,
relay access, and GitHub proposal fallback are separate profiles. The client
must probe actual tools and never infer write permission from plugin presence.

The private Milestone 8 profile publishes only the existing read and status MCP
tools. Mutation and nomination tools are absent from its tool registry, not
merely hidden by client annotations. Direct mutation remains disabled unless a
separate, explicitly authorized profile is implemented and tested.

Use ChatGPT web for the private profile. Enable developer mode under **Settings
→ Security and login**, create a developer-mode app, choose **Tunnel** as the
connection, and select the tunnel associated with the intended ChatGPT
workspace and Platform organization. Developer-mode and tunnel permissions are
separate account controls. Refresh the app after a server tool-contract change;
do not rely on a previously discovered tool snapshot.

Current official OpenAI documentation does not establish an equivalent mobile
setup path for this private plugin profile. Treat mobile, voice, agent mode, and
other surfaces as unsupported until an account-side capability probe proves the
exact surface, model, app snapshot, and tool list. Fall back to a supported web
chat rather than weakening the server boundary.

The target Pro account enabled developer mode, created the private app, and
successfully invoked the tunnel-backed `echo` tool from ChatGPT web. The
operator observed the exact response `chatgpt tunnel echo verified`. This
confirms the private read-only path without changing the direct-mutation
boundary.

Secure MCP Tunnel runs inside the Memory Node trust boundary and connects
outbound to OpenAI. It forwards to the dedicated authenticated read-only MCP
route and requires no public inbound listener. It is for private connections
and developer-mode testing, not public plugin submission or distribution.

The GitHub proposal fallback is a separately gated transport. No current
capability record in this repository establishes a supported create-file action
for the target account, so keep this fallback disabled unless that exact
account exposes and successfully re-probes one. A historical probe is not
durable authorization. When enabled, require explicit approval, create one new
bounded proposal at one UUIDv7 path, and never update or delete an existing
path.

See the [dated capability probe](capability-probe-2026-08-03.md) for source links
and complete Milestone 0 acceptance evidence. Re-run that probe when account,
workspace, model, app, or OpenAI capability policy changes.

Current references:

- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [Connect and test a plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt)
