# ChatGPT setup

ChatGPT integration is capability-gated. Private read access, direct writes,
relay access, and GitHub proposal fallback are separate profiles. The client
must probe actual tools and never infer write permission from plugin presence.

As observed on 2026-08-03, Pro custom MCP access is documented as read/fetch
only, and custom MCP apps are web-only. Direct mutation remains disabled unless
an account-side capability test proves otherwise. Secure MCP Tunnel is suitable
for private testing, but not as a public plugin endpoint.

The target Pro account enabled developer mode, created the private app, and
successfully invoked the tunnel-backed `echo` tool from ChatGPT web. The
operator observed the exact response `chatgpt tunnel echo verified`. This
confirms the private read-only path without changing the direct-mutation
boundary.

See the [dated capability probe](capability-probe-2026-08-03.md) for source links
and complete Milestone 0 acceptance evidence.
