# Codex setup

Codex clients use either the private node or public relay with one identity and
credential per host or environment. Retrieval may be approved automatically;
mutations and destructive forgetting require tool-specific approval policy.

The installed Codex 0.146.0 release supports the private Streamable HTTP profile:

```toml
[mcp_servers.kivra_memory]
url = "https://memory.example/mcp"
bearer_token_env_var = "KIVRA_MEMORY_TOKEN"
required = true
default_tools_approval_mode = "writes"
startup_timeout_sec = 10
tool_timeout_sec = 60
```

Keep tokens in environment-backed configuration. Use tool allowlists and
per-tool approval overrides when a client needs less than the full capability
profile. See the [dated capability probe](capability-probe-2026-08-03.md) before
copying this profile to another Codex release.
