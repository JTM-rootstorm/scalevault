# ChatGPT setup

ChatGPT integration is capability-gated. Private read access, direct writes,
relay access, and GitHub proposal fallback are separate profiles. The client
must probe actual tools and never infer write permission from plugin presence.

As observed on 2026-08-03, Pro custom MCP access is documented as read/fetch
only, and custom MCP apps are web-only. Direct mutation remains disabled unless
an account-side capability test proves otherwise. Secure MCP Tunnel is suitable
for private testing, but not as a public plugin endpoint.

See the [dated capability probe](capability-probe-2026-08-03.md) for source links
and the remaining account-side checks.
