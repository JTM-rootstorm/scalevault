# Milestone 8 acceptance checklist

- Review date: 2026-08-09 (America/Chicago)
- Status: Complete for the private ChatGPT read profile and capability-gated Pro write bridge
- Implementation baseline: `b5d6ce9`

This checklist is content-free. It records implementation and operational
evidence without memory statements, canonical identity identifiers, bearer
tokens, private hostnames, repository coordinates, or database credentials.

## Exit criteria

| Requirement | Status | Evidence |
|---|---|---|
| Fresh supported ChatGPT web read | Verified | A fresh ChatGPT web chat invoked the installed `kiv-memory` developer app and completed a bounded `memory_search` for a unique nonexistent canary with zero hits. The control-plane tunnel recorded one successful `tools/call` response. |
| No direct ChatGPT mutation | Verified | The dedicated ChatGPT MCP route exposes exactly ten read and status tools. Nomination and mutation tools are absent from the registry, and the secure-tunnel credential has no write scopes. |
| Capability-gated GitHub proposal fallback | Verified and disabled by default | The create-only proposal contract, immutable retry behavior, bounded history verification, ingestion status, and current-capability checks are implemented and tested. The fallback remains unavailable unless the live account exposes the exact create-file action and the user approves the individual proposal. |
| Safe proposal ingestion and status | Verified | The pinned ingress path reuses the canonical nomination and selection engine, enforces immutable provider identity and sensitivity limits, terminalizes duplicate-safe results, and exposes only bounded status. |
| No public inbound listener | Verified | Secure MCP Tunnel polls outbound from the canonical node and forwards only to the authenticated loopback ChatGPT route. API and tunnel health surfaces remain loopback-only. |

## Fresh web-chat canary

The live tunnel is registered as `kiv-memory` and is associated with one
intended Platform organization and one ChatGPT workspace. Both the Memory Node
API and tunnel service were active, the tunnel reported `live` and `ready`, and
the service had recorded no restarts.

Before the account-side test, the dedicated loopback ChatGPT route initialized
as `ScaleVault ChatGPT Read Node`, exposed the exact ten-tool read-only surface,
and returned zero hits for the unique `fresh-chat-canary-<UUIDv7>` query. The
same marker was then requested from a fresh ChatGPT web conversation through
the installed `kiv-memory` app. ChatGPT displayed its host wrapper as
`codex_apps (kiv-memory plugin)` and reported a hit count of zero.

The tunnel's payload-free metrics independently recorded one successful
control-plane `tools/call` with status `200`. A bounded post-call scan of the
Memory Node API and tunnel journals found none of the canary marker, bearer
grammar, or `Authorization` header name. No canonical memory, credential,
service configuration, or repository state was mutated by the canary.

This no-result canary verifies the real web-chat read dispatch, tunnel routing,
request authentication, bounded retrieval response, and log-redaction boundary
without manufacturing an active synthetic memory. It does not claim that the
nonexistent marker was stored or that any private memory content was returned.

## Security and capability boundary

The ChatGPT surface remains physically read-only at MCP discovery. Retrieved
memory is untrusted data and cannot supply instructions or widen the request.
Candidate visibility remains disabled for the tunnel credential, preventing
unreviewed Genesis or assistant-observation candidates from entering normal
ChatGPT retrieval.

The GitHub proposal fallback is a separate third-party transport. Historical
create-file evidence does not grant current authority. Each future proposal
still requires a current account-side capability probe, explicit per-action
approval, zero sensitivity, one create-only path, and later canonical status
resolution.

## Documentation validation

This acceptance update changes documentation and repository guidance only. It
does not modify code, schemas, migrations, generated artifacts, build inputs,
deployment configuration, or runtime behavior. The publication gate therefore
uses documentation-proportional validation rather than the executable test
suite:

```bash
git diff --check
```
